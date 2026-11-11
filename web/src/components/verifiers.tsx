'use client';

import { motion, useReducedMotion, useScroll, useTransform } from 'motion/react';
import { useLayoutEffect, useRef, useState } from 'react';
import type { Act } from '../stageshow/kit/act';
import { Stage } from '../stageshow/kit/stage';
import { Caret, Prompt, Window } from '../stageshow/kit/window';
import { Reveal } from './site';
import './verifiers.css';

// One terminal, the only window on the page: a relying party asks for two
// claims and prints what it verified. It enters from the tile's top-left
// gutter and runs off the other two edges. The lines arrive once, as the
// section scrolls in.

const points = [
  {
    title: 'Ask in a line.',
    body: 'A small claim language covers age, nationality, issuer, expiry and birth date.',
  },
  {
    title: 'Pin what you trust.',
    body: 'A verifier fixes the issuer, the claims it asked for, a fresh timestamp and the roots it accepts.',
  },
  {
    title: 'Check it anywhere.',
    body: 'Verify a proof off-chain, or let a Solana program do it and record the result for others.',
  },
  {
    title: 'Give it to an agent.',
    body: 'The passport CLI ships an MCP server and an agent skill. Setup and scan work today.',
  },
];

type Scene = { step: number };
const script = async (a: Act<Scene>) => {
  await a.wait(600);
  await a.set({ step: 1 });
  await a.wait(900);
  await a.set({ step: 2 });
  await a.wait(1400);
  await a.set({ step: 3 });
};

const on = (value: boolean) => (value ? '' : undefined);

function Terminal({ step }: { step: number }) {
  return (
    <Window chrome="terminal" title="relying-party — zsh" className="vf-window">
      <Prompt path="~/passport">just relying-party &apos;age.gte(18)&apos; nationality</Prompt>
      <div className="vf-line dim" data-show={on(step >= 1)}>
        request &nbsp;openid4vp://?request_uri=…
      </div>
      <div className="vf-line dim" data-show={on(step >= 2)}>
        waiting for the holder…
      </div>
      <div className="vf-line ok" data-show={on(step >= 3)}>
        ✓ proof verified
      </div>
      <div className="vf-line" data-show={on(step >= 3)}>
        &nbsp;&nbsp;age.gte(18) &nbsp;&nbsp;true
      </div>
      <div className="vf-line" data-show={on(step >= 3)}>
        &nbsp;&nbsp;nationality &nbsp;&nbsp;UTO
      </div>
      <Prompt path="~/passport">
        <Caret />
      </Prompt>
    </Window>
  );
}

/** For the people on the other side of the request: verifiers and their agents. */
export function Verifiers() {
  const tile = useRef<HTMLDivElement>(null);
  const reduced = useReducedMotion();
  // Zero until measured, so the stage is never drawn at a guessed width and then resized.
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const node = tile.current;
    if (!node) return;
    const measure = () => setWidth(Math.max(1, Math.round(node.getBoundingClientRect().width)));
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  const { scrollYProgress } = useScroll({ target: tile, offset: ['start end', 'end start'] });
  const y = useTransform(scrollYProgress, [0, 1], [40, -40]);

  return (
    <section className="section shell" id="verifiers" aria-labelledby="verifiers-heading">
      <Reveal className="heading">
        <p className="tag">For verifiers</p>
        <h2 id="verifiers-heading">
          Ask a question.
          <br />
          Get a proof back.
        </h2>
        <p>
          A website, an app or an agent sends an OpenID4VP request and receives a compact proof of
          the answers. No document, no photo, nothing to store.
        </p>
      </Reveal>

      <div ref={tile} className="vf-tile" aria-hidden>
        {width > 0 && (
          <motion.div className="vf-picture" style={reduced ? undefined : { y }}>
            <Stage<Scene>
              width={width}
              height={440}
              initial={{ step: 0 }}
              poster={{ step: 3 }}
              play="once"
              script={script}
              className="vf-stage"
            >
              {(scene) => <Terminal step={scene.step} />}
            </Stage>
          </motion.div>
        )}
      </div>

      <ul className="vf-points">
        {points.map((point, index) => (
          <li key={point.title}>
            <Reveal delay={index * 0.08}>
              <h3>{point.title}</h3>
              <p>{point.body}</p>
            </Reveal>
          </li>
        ))}
      </ul>
    </section>
  );
}
