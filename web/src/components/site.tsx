'use client';

import { ChevronDown, Github, Star } from 'lucide-react';
import { MotionConfig, motion, useScroll, useTransform } from 'motion/react';
import Image from 'next/image';
import { useRef, type ReactNode } from 'react';
import { Bento } from './bento';
import { Story } from './story';
import { Verifiers } from './verifiers';

export const REPOSITORY = 'https://github.com/lgalabru/passport';

const links = [
  { href: '#iphone', label: 'iPhone' },
  { href: '#features', label: 'Features' },
  { href: '#verifiers', label: 'Verifiers' },
  { href: '#questions', label: 'Questions' },
];

const steps = ['Read the chip', 'Get asked', 'Prove one fact'];

const questions = [
  {
    question: 'What is Passport?',
    answer:
      'Passport reads the NFC chip in an ePassport or ID card with an iPhone or a Flipper Zero and checks the issuing state’s signatures. When a website, an app or an agent asks a question such as “is this person 18 or older?”, it answers with a zero-knowledge proof of that one fact.',
  },
  {
    question: 'What leaves my phone?',
    answer:
      'The proof and the answers you agreed to share. The app shows exactly what would be shared before you approve. Your name, photo and document number stay on the device.',
  },
  {
    question: 'Can I rely on it today?',
    answer:
      'No. This is experimental research code and nothing here has been audited. The proving keys come from a fixed seed, so anyone can forge proofs. There is no shared registry yet: each phone keeps its own, so a proof today only shows that the claims hold for a document enrolled on that phone, not that a state issued it. Request-object signatures are not checked. Formats, circuits and APIs will change without notice.',
  },
  {
    question: 'Which documents work?',
    answer:
      'ePassports and ID cards that follow ICAO 9303. Reading and checking the signatures works natively. Enrollment in zero knowledge covers RSA-2048 document signers and RSA-1024 chip keys for now.',
  },
  {
    question: 'How does a verifier check a proof?',
    answer:
      'Proofs are Groth16 over BN254, with circuits written in Rust using xark. Anyone can check one off-chain. A Solana program can check one on-chain; recording it in the Solana Attestation Service is the next step. The registry program runs in a local test validator today.',
  },
  {
    question: 'Does this website read my passport?',
    answer:
      'No. This website is a product preview. It does not read a document, use NFC or the camera, or collect anything. The illustrations use the ICAO specimen passport and sample data.',
  },
];

/** A block that rises into place the first time it scrolls into view. */
export function Reveal({
  children,
  delay = 0,
  className,
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
}) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 28 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '0px 0px -12% 0px' }}
      transition={{ duration: 0.7, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
}

/**
 * The floating navigation. `stars` is the repository's star count, read on the
 * server; it is left out when GitHub could not be reached.
 */
function Header({ stars }: { stars?: number | null }) {
  return (
    <>
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="site-header">
        <nav className="navigation" aria-label="Main navigation">
          <a className="brand" href="#" aria-label="Passport home">
            <Image src="/passport-icon.png" alt="" width={28} height={28} />
            passport
          </a>
          <div className="nav-links">
            {links.map((link) => (
              <a key={link.href} href={link.href}>
                {link.label}
              </a>
            ))}
          </div>
          <a className="nav-badge" href={REPOSITORY} target="_blank" rel="noreferrer">
            <Github size={16} />
            Experimental
            {stars != null && (
              <span className="nav-stars" aria-label={`${stars} GitHub stars`}>
                <Star size={12} fill="currentColor" />
                {new Intl.NumberFormat('en', { notation: 'compact' }).format(stars)}
              </span>
            )}
          </a>
        </nav>
      </header>
    </>
  );
}

function Hero() {
  const ref = useRef<HTMLElement>(null);
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start start', 'end start'] });
  const y = useTransform(scrollYProgress, [0, 1], [0, 160]);
  return (
    <section ref={ref} className="hero" aria-labelledby="hero-heading">
      <motion.div className="hero-copy shell" style={{ y }}>
        <p className="tag">For iPhone and Flipper Zero</p>
        <h1 id="hero-heading">
          Prove it.
          <br />
          <span>Don&rsquo;t show it.</span>
        </h1>
        <p className="lead">
          Passport turns the chip in your passport into private, verifiable claims. Answer &ldquo;18
          or older?&rdquo; with a zero-knowledge proof. Your name, photo and document number stay on
          your phone.
        </p>
        <ul className="chips">
          {steps.map((label, index) => (
            <li key={label}>
              <span>{index + 1}</span>
              {label}
            </li>
          ))}
        </ul>
      </motion.div>
    </section>
  );
}

function Questions() {
  return (
    <section className="section shell narrow" id="questions" aria-labelledby="questions-heading">
      <Reveal className="heading">
        <h2 id="questions-heading">Good questions.</h2>
      </Reveal>
      <div className="faq">
        {questions.map((item) => (
          <details key={item.question}>
            <summary>
              {item.question}
              <span className="faq-toggle">
                <ChevronDown size={18} />
              </span>
            </summary>
            <p>{item.answer}</p>
          </details>
        ))}
      </div>
    </section>
  );
}

function Closing() {
  return (
    <section className="shell" id="status" aria-labelledby="status-heading">
      <Reveal className="closing">
        <Image src="/passport-icon.png" alt="Passport app icon" width={72} height={72} />
        <p className="tag">Experimental research code</p>
        <h2 id="status-heading">
          Not audited.
          <br />
          Not for anything real.
        </h2>
        <p>
          Passport is open research. The keys are development keys and the registry is local. Read
          the design and the security notes before you build on it.
        </p>
        <a className="closing-link" href={REPOSITORY} target="_blank" rel="noreferrer">
          <Github size={18} />
          Read the code
        </a>
      </Reveal>
    </section>
  );
}

function Footer() {
  return (
    <footer className="site-footer shell">
      <a className="brand" href="#" aria-label="Passport home">
        passport
      </a>
      <p>Prove it. Don&rsquo;t show it.</p>
      <span>MIT licensed.</span>
    </footer>
  );
}

/** The public product page, with no account collection or third-party analytics. */
export function Site({ stars }: { stars?: number | null }) {
  return (
    <MotionConfig reducedMotion="user">
      <Header stars={stars} />
      <main id="main">
        <Hero />
        <Story />
        <p className="note shell">
          Illustration with the ICAO specimen passport and sample data. Nothing is read or sent.
        </p>
        <section className="section shell" id="features" aria-labelledby="features-heading">
          <Reveal className="heading">
            <h2 id="features-heading">
              One answer.
              <br />
              Nothing else.
            </h2>
            <p>
              A scan of your passport tells a website everything about you. A proof tells it the one
              thing it asked.
            </p>
          </Reveal>
          <Bento />
        </section>
        <Verifiers />
        <Questions />
        <Closing />
      </main>
      <Footer />
    </MotionConfig>
  );
}
