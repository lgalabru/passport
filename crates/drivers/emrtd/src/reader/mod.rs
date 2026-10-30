//! The read state machine.
//!
//! SELECT application → GET CHALLENGE → EXTERNAL AUTHENTICATE (BAC) → SELECT
//! file → READ BINARY in 32-byte chunks. The reader never touches a UI or
//! storage directly: progress goes to an [`Observer`], bytes to a
//! [`ByteSink`], and the result comes back as a [`ReadOutcome`].
//!
//! * [`host`]: the traits a platform implements ([`Transport`], [`Observer`],
//!   [`ByteSink`]).
//! * [`commands`]: APDU templates.

pub mod commands;
pub mod host;

use alloc::string::String;
use alloc::vec::Vec;

use crate::types::{
    Asn1Error, DataGroup, IMAGE_LOOKAHEAD, MAX_DG_BUFFER, MrzKey, MrzRecord, READ_CHUNK_SIZE,
    ReadTarget, ReaderError, ReaderEvent, ResponseApdu,
};

use crate::lds::asn1::{Com, file_total_size, parse_com, parse_dg1};
use crate::lds::image::{ImageFormat, detect_image_format};
use crate::lds::mrz::parse_record;
use crate::reader::host::{ByteSink, Level, Observer, Transport};
use crate::secure_messaging::SecureMessaging;
use crate::store::artifact_name;

const TAG: &str = "reader";

/// A data group that was streamed to the [`ByteSink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedFile {
    /// Name handed to [`ByteSink::open`], e.g. `L898902C-DG2.jpeg`; the host
    /// prepends its data directory.
    pub name: String,
    /// Bytes written to the sink.
    pub bytes: usize,
    /// Detected container; [`ImageFormat::Raw`] for plain dumps.
    pub format: ImageFormat,
}

/// What a successful read produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // one value per read; boxing would only add noise
pub enum ReadOutcome {
    /// `EF.COM`, kept in RAM. `parsed` is the decoded form, or why it could not
    /// be decoded (the UI can still show `raw`).
    Com {
        raw: Vec<u8>,
        parsed: Result<Com, Asn1Error>,
    },
    /// DG1, kept in RAM.
    Dg1 {
        raw: Vec<u8>,
        record: Result<MrzRecord, Asn1Error>,
    },
    /// Any other data group, written to the sink.
    Saved(SavedFile),
}

/// One read attempt against one card.
pub struct Reader<'a> {
    transport: &'a mut dyn Transport,
    observer: &'a mut dyn Observer,
    sink: &'a mut dyn ByteSink,
    key: MrzKey,
    messaging: SecureMessaging,
    secure: bool,
}

impl core::fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reader")
            .field("secure", &self.secure)
            .finish_non_exhaustive()
    }
}

impl<'a> Reader<'a> {
    pub fn new(
        transport: &'a mut dyn Transport,
        observer: &'a mut dyn Observer,
        sink: &'a mut dyn ByteSink,
        key: MrzKey,
    ) -> Self {
        let messaging = SecureMessaging::new(&key);
        Self {
            transport,
            observer,
            sink,
            key,
            messaging,
            secure: false,
        }
    }

    /// Use caller-chosen BAC nonces instead of the all-zero default.
    pub fn with_messaging(mut self, messaging: SecureMessaging) -> Self {
        self.messaging = messaging;
        self
    }

    /// Run the whole sequence for `target`. A failure is also reported to the
    /// observer as [`ReaderEvent::Failed`], so callers can use either channel.
    pub fn read(&mut self, target: ReadTarget) -> Result<ReadOutcome, ReaderError> {
        self.secure = false;
        match self.run(target) {
            Ok(outcome) => {
                self.observer.event(ReaderEvent::Finished);
                Ok(outcome)
            }
            Err(error) => {
                self.observer.event(ReaderEvent::Failed(error.clone()));
                Err(error)
            }
        }
    }

    /// Active Authentication: BAC, then INTERNAL AUTHENTICATE with
    /// `challenge`. Returns the chip's signature, which only the chip's
    /// private key (behind DG15) can produce; check it with the DG15 key.
    pub fn active_authenticate(&mut self, challenge: &[u8; 8]) -> Result<Vec<u8>, ReaderError> {
        self.secure = false;
        let result = self.establish().and_then(|()| {
            let answer = self.send(&commands::internal_authenticate(challenge))?;
            if answer.data.is_empty() {
                return Err(ReaderError::ShortResponse);
            }
            Ok(answer.data)
        });
        match &result {
            Ok(_) => self.observer.event(ReaderEvent::Finished),
            Err(error) => self.observer.event(ReaderEvent::Failed(error.clone())),
        }
        result
    }

    /// SELECT the application and run BAC; secure messaging is on after.
    fn establish(&mut self) -> Result<(), ReaderError> {
        self.observer
            .event(ReaderEvent::Detected(self.transport.protocol()));

        self.send(&commands::select_application())?;
        let challenge = self.send(&commands::get_challenge())?;
        self.messaging.set_challenge(&challenge.data)?;

        let payload = self.messaging.authenticate_payload();
        let answer = self.send(&commands::external_authenticate(payload))?;
        self.messaging.complete_authentication(&answer.data)?;
        self.secure = true;
        self.observer.log(
            Level::Info,
            TAG,
            format_args!("Mutual authentication success"),
        );
        self.observer.event(ReaderEvent::Authenticated);
        Ok(())
    }

    fn run(&mut self, target: ReadTarget) -> Result<ReadOutcome, ReaderError> {
        self.establish()?;
        self.send(&commands::select_file(target.file_id()))?;

        match target {
            ReadTarget::Com => {
                let raw = self.read_buffered()?;
                let parsed = parse_com(&raw);
                Ok(ReadOutcome::Com { raw, parsed })
            }
            ReadTarget::Dg(DataGroup::Dg1) => {
                let raw = self.read_buffered()?;
                self.observer.log_hex(Level::Debug, TAG, "DG1", &raw);
                let record = parse_dg1(&raw).and_then(parse_record);
                Ok(ReadOutcome::Dg1 { raw, record })
            }
            ReadTarget::Dg(group) if group.is_image() => self.save_image(target),
            ReadTarget::Dg(_) | ReadTarget::Sod => self.save_generic(target),
        }
    }

    /// One command/response exchange, with secure messaging when active.
    /// Fails on a non-success status word, outer or protected.
    fn send(&mut self, apdu: &crate::types::CommandApdu) -> Result<ResponseApdu, ReaderError> {
        let tx = if self.secure {
            self.messaging.wrap(apdu)?
        } else {
            apdu.to_bytes()
        };
        let rx = self.transport.transceive(&tx)?;

        let outer = ResponseApdu::from_bytes(&rx).ok_or(ReaderError::ShortResponse)?;
        if !outer.sw.is_success() {
            self.observer
                .log(Level::Warn, TAG, format_args!("Invalid SW {}", outer.sw));
            return Err(ReaderError::StatusWord(outer.sw));
        }
        if !self.secure {
            return Ok(outer);
        }

        let inner = self.messaging.unwrap(&rx)?;
        if !inner.sw.is_success() {
            self.observer.log(
                Level::Warn,
                TAG,
                format_args!("Invalid protected SW {}", inner.sw),
            );
            return Err(ReaderError::StatusWord(inner.sw));
        }
        Ok(inner)
    }

    /// READ BINARY of up to `len` bytes at `offset`. Returns what the card sent;
    /// an empty answer is an error so a short file cannot stall the loop.
    fn read_binary(&mut self, offset: usize, len: usize) -> Result<Vec<u8>, ReaderError> {
        if offset > 0xFFFF || !commands::offset_is_valid(offset as u16) {
            return Err(ReaderError::OffsetTooLarge(offset));
        }
        let response = self.send(&commands::read_binary(offset as u16, len as u8))?;
        if response.data.is_empty() {
            return Err(ReaderError::ShortResponse);
        }
        let mut data = response.data;
        data.truncate(len);
        Ok(data)
    }

    /// Read the 4-byte header and return the first bytes plus the total file size.
    fn read_header(&mut self) -> Result<(Vec<u8>, usize), ReaderError> {
        let header = self.read_binary(0, 4)?;
        let total = file_total_size(&header).ok_or(Asn1Error::UnsupportedLength(
            header.get(1).copied().unwrap_or(0) as usize,
        ))?;
        Ok((header, total))
    }

    /// Whole file into RAM (`EF.COM`, DG1), bounded by `MAX_DG_BUFFER`.
    fn read_buffered(&mut self) -> Result<Vec<u8>, ReaderError> {
        let (header, total) = self.read_header()?;
        if total > MAX_DG_BUFFER {
            return Err(Asn1Error::UnsupportedLength(total).into());
        }
        let mut data = header;
        while data.len() < total {
            self.observer.event(ReaderEvent::Reading {
                offset: data.len(),
                total,
            });
            let le = READ_CHUNK_SIZE.min(total - data.len());
            let chunk = self.read_binary(data.len(), le)?;
            data.extend_from_slice(&chunk);
        }
        Ok(data)
    }

    /// DG2/DG7: sniff the image container in a 120-byte look-ahead, then stream
    /// from the image magic to the end of the file.
    fn save_image(&mut self, target: ReadTarget) -> Result<ReadOutcome, ReaderError> {
        // Some chips mishandle a single 120-byte read, so read two halves.
        let half = IMAGE_LOOKAHEAD / 2;
        let mut lookahead = self.read_binary(0, half)?;
        lookahead.extend(self.read_binary(half, half)?);
        self.observer.event(ReaderEvent::Reading {
            offset: 0,
            total: 0,
        });

        let total = file_total_size(&lookahead).ok_or(Asn1Error::UnsupportedLength(
            lookahead.get(1).copied().unwrap_or(0) as usize,
        ))?;
        let (format, start) = detect_image_format(&lookahead);
        self.stream_to_sink(target, format, start, total)
    }

    /// Any other data group: write the header, then the rest, as `.bin`.
    fn save_generic(&mut self, target: ReadTarget) -> Result<ReadOutcome, ReaderError> {
        let (header, total) = self.read_header()?;
        self.observer
            .event(ReaderEvent::Reading { offset: 0, total });
        self.stream_header_and_rest(target, header, total)
    }

    fn stream_to_sink(
        &mut self,
        target: ReadTarget,
        format: ImageFormat,
        start: usize,
        total: usize,
    ) -> Result<ReadOutcome, ReaderError> {
        self.open_sink(target, format)?;
        let result = self.copy_range(start, total);
        self.finish_sink(target, format, result)
    }

    fn stream_header_and_rest(
        &mut self,
        target: ReadTarget,
        header: Vec<u8>,
        total: usize,
    ) -> Result<ReadOutcome, ReaderError> {
        self.open_sink(target, ImageFormat::Raw)?;
        let result = self
            .sink
            .write(&header)
            .map_err(ReaderError::from)
            .and_then(|written| Ok(written + self.copy_range(header.len(), total)?));
        self.finish_sink(target, ImageFormat::Raw, result)
    }

    fn open_sink(&mut self, target: ReadTarget, format: ImageFormat) -> Result<(), ReaderError> {
        let name = artifact_name(&self.key, target, format.extension());
        self.observer
            .log(Level::Info, TAG, format_args!("Writing to {name}"));
        self.sink.open(&name)?;
        Ok(())
    }

    /// Close the sink whatever happened, then report the first failure.
    fn finish_sink(
        &mut self,
        target: ReadTarget,
        format: ImageFormat,
        result: Result<usize, ReaderError>,
    ) -> Result<ReadOutcome, ReaderError> {
        let closed = self.sink.close();
        let bytes = result?;
        closed?;
        Ok(ReadOutcome::Saved(SavedFile {
            name: artifact_name(&self.key, target, format.extension()),
            bytes,
            format,
        }))
    }

    /// Copy `[from, total)` of the selected file to the sink, returning bytes written.
    fn copy_range(&mut self, from: usize, total: usize) -> Result<usize, ReaderError> {
        let mut offset = from;
        let mut written = 0;
        while offset < total {
            let le = READ_CHUNK_SIZE.min(total - offset);
            let chunk = self.read_binary(offset, le)?;
            written += self.sink.write(&chunk)?;
            offset += chunk.len();
            self.observer.event(ReaderEvent::Reading { offset, total });
        }
        Ok(written)
    }
}
