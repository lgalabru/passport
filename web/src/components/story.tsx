'use client';

import { CalendarCheck, Hand, Lock, Nfc, ScanFace } from 'lucide-react';
import {
  motion,
  useMotionValueEvent,
  useReducedMotion,
  useScroll,
  useTransform,
  type MotionValue,
} from 'motion/react';
import Image from 'next/image';
import { useRef, useState } from 'react';
import { Button } from '../stageshow/kit/controls/Button';
import { Avatar } from '../stageshow/kit/parts/Avatar';
import { Check } from '../stageshow/kit/parts/Check';
import { Spinner } from '../stageshow/kit/parts/Spinner';
import { Phone } from '../stageshow/kit/phone';
import { Stage } from '../stageshow/kit/stage';
import { Bar } from '../stageshow/kit/window';
import './story.css';

// The story, written before it was built. One tall section, one pinned
// iPhone, and the page's scroll is the clock:
//
//   Scroll     Chapter         On the iPhone                  Around it
//   0.00-0.30  1 Read          the ring fills, two checks     the passport slides under the phone
//   0.30-0.55  2 Ask           one request, one answer        the passport leaves
//   0.55-0.80  3 Prove         Face ID, then "Proved"         -
//   0.80-1.00  Shared          what stays on the phone        -
//
// The phone runs off the foot of the viewport, so every scene keeps its
// action in the top two thirds of the screen.

const AT = {
  bookIn: 0.02,
  bookSet: 0.1,
  scanEnd: 0.22,
  added: 0.24,
  ask: 0.3,
  prove: 0.55,
  faceId: 0.6,
  proved: 0.7,
  shared: 0.8,
};

/** The sample verifier. Fictional, like the request it sends. */
const VERIFIER = 'Cellar Door';

const chapters = [
  {
    kicker: 'Step 1 · Read',
    title: 'Tap your passport.',
    body: 'The iPhone reads the chip over NFC and checks the issuing state’s signatures. The chip signs a challenge too, so a copy of its files would not pass.',
  },
  {
    kicker: 'Step 2 · Ask',
    title: 'One question at a time.',
    body: 'A website, an app or an agent sends a request. Passport shows exactly what would be shared before anything leaves.',
  },
  {
    kicker: 'Step 3 · Prove',
    title: 'Proved on your phone.',
    body: 'After Face ID, the zero-knowledge proof is made on the device. It takes about 0.2 seconds.',
  },
  {
    kicker: 'Shared',
    title: 'One fact leaves.',
    body: 'The verifier learns that you are 18 or older. Your birthday, your name and the passport itself stay on the phone.',
  },
];

/** The progress rail: one segment per step, filled over the stretch of scroll it covers. */
const rail: { label: string; from: number; to: number }[] = [
  { label: 'Read', from: AT.bookSet, to: AT.added },
  { label: 'Ask', from: AT.ask, to: AT.prove },
  { label: 'Prove', from: AT.prove, to: AT.proved },
];

type Moment = {
  chapter: number;
  reading: boolean;
  added: boolean;
  faceId: boolean;
  proved: boolean;
};

const momentAt = (p: number): Moment => ({
  chapter: p < AT.ask ? 0 : p < AT.prove ? 1 : p < AT.shared ? 2 : 3,
  reading: p >= AT.bookSet,
  added: p >= AT.added,
  faceId: p >= AT.faceId,
  proved: p >= AT.proved,
});

const same = (a: Moment, b: Moment) =>
  (Object.keys(a) as (keyof Moment)[]).every((key) => a[key] === b[key]);

const on = (value: boolean) => (value ? '' : undefined);

function Screen({ moment, scan }: { moment: Moment; scan: MotionValue<number> }) {
  const { chapter, reading, added, faceId, proved } = moment;
  return (
    <div className="st-screen">
      {/* 1. Read */}
      <div className="st-view" data-show={on(chapter === 0)}>
        <div className="st-title">Add Your Passport</div>
        <span className="st-ring" data-done={on(added)}>
          <svg viewBox="0 0 120 120">
            <circle cx="60" cy="60" r="54" />
            <motion.circle
              className="st-ring-arc"
              cx="60"
              cy="60"
              r="54"
              style={{ pathLength: scan }}
            />
          </svg>
          <Nfc size={44} strokeWidth={1.5} />
        </span>
        <div className="st-prompt">
          {added ? 'Passport Added' : reading ? 'Reading the chip…' : 'Ready to read'}
        </div>
        <div className="st-hint">
          {added ? 'Specimen · Utopia' : 'Hold your passport near the top of your iPhone'}
        </div>
        <div className="st-card st-checks" data-show={on(added)}>
          <div className="st-line">
            <span>Signed by the issuing state</span>
            <Check on={added} size={22} />
          </div>
          <div className="st-line">
            <span>Chip is genuine</span>
            <Check on={added} size={22} />
          </div>
        </div>
      </div>

      {/* 2. Ask */}
      <div className="st-view" data-show={on(chapter === 1)}>
        <Avatar name={VERIFIER} size={60} tone="ink" className="st-who" />
        <div className="st-prompt st-prompt--large">{VERIFIER}</div>
        <div className="st-hint">wants you to verify</div>
        <div className="st-secure">
          <Lock size={13} strokeWidth={2.2} />
          Sent over HTTPS
        </div>
        <div className="st-card">
          <div className="st-card-label">Shared with {VERIFIER}</div>
          <div className="st-line">
            <span className="st-claim">
              <CalendarCheck size={20} strokeWidth={1.8} />
              You are 18 or older
            </span>
            <b>Yes</b>
          </div>
        </div>
        <div className="st-note">
          <Hand size={18} strokeWidth={1.8} />
          <span>
            {VERIFIER} receives a zero-knowledge proof of this answer. Your name, photo and document
            number stay on this iPhone.
          </span>
        </div>
        <Button className="st-button st-button--fill">Share</Button>
        <Button className="st-button">Don&rsquo;t Share</Button>
      </div>

      {/* 3. Prove */}
      <div className="st-view" data-show={on(chapter === 2)}>
        <div className="st-title">{VERIFIER}</div>
        <span className="st-disc" data-on={on(proved)}>
          <ScanFace size={46} strokeWidth={1.5} />
        </span>
        <div className="st-prompt">
          {proved ? 'Proved in 0.2 s' : faceId ? 'Creating Proof…' : 'Face ID'}
        </div>
        <span className="st-wait" data-show={on(faceId && !proved)}>
          <Spinner size={18} />
        </span>
        <div className="st-card st-checks" data-show={on(proved)}>
          <div className="st-line">
            <span>You are 18 or older</span>
            <b>Yes</b>
          </div>
          <div className="st-line">
            <span>Proof system</span>
            <b>Groth16</b>
          </div>
        </div>
      </div>

      {/* 4. Shared */}
      <div className="st-view" data-show={on(chapter === 3)}>
        <div className="st-title">{VERIFIER}</div>
        <Check on={chapter === 3} size={72} className="st-done" />
        <div className="st-prompt st-prompt--large">Shared</div>
        <div className="st-hint">{VERIFIER} has your proof.</div>
        <div className="st-card">
          <div className="st-card-label">Stays on this iPhone</div>
          {['Name', 'Photo', 'Document number'].map((label, index) => (
            <div key={label} className="st-line">
              <span>{label}</span>
              <span className="st-kept">
                <Bar w={[92, 44, 74][index]} h={8} tone={3} />
                <Lock size={15} strokeWidth={2} />
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function RailStep({
  p,
  step,
  active,
}: {
  p: MotionValue<number>;
  step: (typeof rail)[number];
  active: boolean;
}) {
  const fill = useTransform(p, [step.from, step.to], [0, 1], { clamp: true });
  return (
    <li data-active={on(active)}>
      <span className="st-rail-track">
        <motion.span style={{ scaleX: fill }} />
      </span>
      {step.label}
    </li>
  );
}

/** The iPhone app told as one request, driven by the page's scroll. */
export function Story() {
  const ref = useRef<HTMLElement>(null);
  const reduced = useReducedMotion();
  const { scrollYProgress: p } = useScroll({ target: ref, offset: ['start start', 'end end'] });
  const [moment, setMoment] = useState<Moment>(momentAt(0));
  useMotionValueEvent(p, 'change', (value) => {
    const next = momentAt(value);
    setMoment((current) => (same(current, next) ? current : next));
  });

  const scan = useTransform(p, [AT.bookSet, AT.scanEnd], [0, 1], { clamp: true });
  // The passport slides under the phone for the read, then leaves the other way.
  const bookX = useTransform(
    p,
    [AT.bookIn, AT.bookSet, AT.added + 0.02, AT.ask + 0.04],
    ['110vw', '0vw', '0vw', '-110vw'],
    { clamp: true },
  );
  const deviceY = useTransform(p, [0, 1], [24, -24]);
  const { chapter } = moment;

  return (
    <section ref={ref} className="st-story" id="iphone" aria-labelledby="story-heading">
      <h2 id="story-heading" className="st-sr">
        How Passport answers a request, step by step
      </h2>
      <div className="st-pin">
        <div className="st-copy">
          <div className="st-chapters">
            {chapters.map((item, index) => (
              <article key={item.kicker} className="st-chapter" data-show={on(chapter === index)}>
                <p className="tag">{item.kicker}</p>
                <h3>{item.title}</h3>
                <p>{item.body}</p>
              </article>
            ))}
          </div>
          <ol className="st-rail" aria-hidden>
            {rail.map((step, index) => (
              <RailStep key={step.label} p={p} step={step} active={chapter === index} />
            ))}
          </ol>
        </div>

        <motion.div
          className="st-device"
          style={reduced ? undefined : { y: deviceY }}
          role="img"
          aria-label="An iPhone running Passport. It reads a specimen passport over NFC, shows a request for one fact, and shares a proof of it after Face ID."
        >
          <motion.span className="st-book" style={{ x: bookX }} aria-hidden>
            <Image src="/passport-cover.png" alt="" width={640} height={640} />
          </motion.span>
          <div aria-hidden>
            <Stage width={380} height={800} className="st-stage" unframed>
              {() => (
                <Phone width={380}>
                  <Screen moment={moment} scan={scan} />
                </Phone>
              )}
            </Stage>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
