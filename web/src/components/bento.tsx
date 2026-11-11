'use client';

import { Lock } from 'lucide-react';
import { motion, useReducedMotion, useScroll, useTransform } from 'motion/react';
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import type { Act } from '../stageshow/kit/act';
import { Badge } from '../stageshow/kit/controls/Badge';
import { Count } from '../stageshow/kit/motion/Count';
import { States } from '../stageshow/kit/motion/States';
import { Check } from '../stageshow/kit/parts/Check';
import { Icon } from '../stageshow/kit/parts/Icon';
import { Row } from '../stageshow/kit/parts/Row';
import { Stage } from '../stageshow/kit/stage';
import { Bar } from '../stageshow/kit/window';
import './bento.css';

// The tile list, written before any tile was built (Stageshow, bento.md):
//
//   Tile     Span   Kind        The one thing                       Moves
//   Private  4 x 1  Hero UI     one answer proved, the rest locked  the answer turns to Proved
//   Speed    2 x 1  Stat        0.2 s, on the one dark tile         counts down
//   Chain    2 x 1  Statement   checkable on Solana                 -
//   Verify   4 x 1  Component   four checks on the document         the ticks land in turn
//   Readers  3 x 1  Collection  what the reader speaks              -
//   Ask      3 x 1  Component   one request link, two claims        -
//
// Six columns, so the rows split 4/2, 2/4 and 3/3 and no two rows share a
// seam. Each picture is its own Stage at 1:1; the ones that move play one
// beat, once, as the grid scrolls in.

const STEP = 110;
const LEAD = 450;

type Beat = { on: boolean };
const before: Beat = { on: false };
const after: Beat = { on: true };
const beat = (index: number) => async (a: Act<Beat>) => {
  await a.wait(LEAD + index * STEP);
  await a.set({ on: true });
};
const scripts = [0, 1, 2, 3].map(beat);

const on = (value: boolean) => (value ? '' : undefined);

/** The tile owns the crop, so each stage is drawn at its tile's own width. */
function usePictureWidth() {
  const ref = useRef<HTMLDivElement>(null);
  // Zero until measured, so a stage is never drawn at a guessed width and then resized.
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const node = ref.current;
    if (!node) return;
    const measure = () => setWidth(Math.max(1, Math.round(node.getBoundingClientRect().width)));
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  return [ref, width] as const;
}

function useSeen<T extends Element>(delay: number) {
  const ref = useRef<T>(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    let timer = 0;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        observer.disconnect();
        timer = window.setTimeout(() => setSeen(true), delay);
      },
      { threshold: 0.4 },
    );
    observer.observe(node);
    return () => {
      observer.disconnect();
      window.clearTimeout(timer);
    };
  }, [delay]);
  return [ref, seen] as const;
}

/** True once the grid is wide enough for its six-column layout; stacked tiles hold still. */
function useColumns() {
  const [columns, setColumns] = useState(false);
  useEffect(() => {
    const query = window.matchMedia('(min-width: 1000px)');
    const update = () => setColumns(query.matches);
    update();
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  }, []);
  return columns;
}

function Tile({
  area,
  lead,
  children,
  picture,
  dark,
  drift = 0,
}: {
  area: string;
  lead?: string;
  children?: ReactNode;
  picture?: ReactNode;
  dark?: boolean;
  /** How far below its place this tile starts, in px, for the staggered parallax. */
  drift?: number;
}) {
  const ref = useRef<HTMLElement>(null);
  const reduced = useReducedMotion();
  const columns = useColumns();
  // Each tile starts lower than its neighbors and settles as it comes up the screen.
  const { scrollYProgress } = useScroll({ target: ref, offset: ['start end', 'start 0.4'] });
  const y = useTransform(scrollYProgress, [0, 1], [drift, 0]);
  return (
    <motion.section
      ref={ref}
      className={`vb-tile vb-tile--${area}`}
      data-dark={on(!!dark)}
      style={reduced || !drift || !columns ? undefined : { y }}
    >
      {lead ? (
        <p className="vb-copy">
          <b>{lead}</b> {children}
        </p>
      ) : (
        children
      )}
      {picture}
    </motion.section>
  );
}

const kept = (width: number) => (
  <span className="vb-kept">
    <Bar w={width} h={8} tone={3} />
    <Lock size={16} strokeWidth={2} />
  </span>
);

function Private() {
  const [picture, width] = usePictureWidth();
  const pad = width < 480 ? 12 : 18;
  return (
    <Tile
      area="private"
      lead="Share the answer. Keep the passport."
      picture={
        <div ref={picture} className="vb-picture" aria-hidden>
          {width > 0 && (
            <Stage<Beat>
              width={width}
              height={270}
              initial={before}
              poster={after}
              play="once"
              script={scripts[0]}
              className="vb-stage"
            >
              {(scene) => (
                <div className="vb-panel vb-panel--large">
                  <Row title={<span className="vb-name">18 or older</span>} pad={pad}>
                    <States
                      value={scene.on ? 'proved' : 'asked'}
                      align="end"
                      states={{
                        asked: <Badge>Asked</Badge>,
                        proved: (
                          <Badge tone="success" icon={<Icon name="check" size={12} />}>
                            Proved
                          </Badge>
                        ),
                      }}
                    />
                  </Row>
                  <Row
                    title={<span className="vb-name vb-name--quiet">Date of birth</span>}
                    pad={pad}
                  >
                    {kept(84)}
                  </Row>
                  <Row title={<span className="vb-name vb-name--quiet">Name</span>} pad={pad}>
                    {kept(118)}
                  </Row>
                </div>
              )}
            </Stage>
          )}
        </div>
      }
    >
      The verifier gets a yes or a no. Everything else on the chip stays where it is.
    </Tile>
  );
}

function Speed() {
  const reduced = useReducedMotion();
  const [ref, seen] = useSeen<HTMLDivElement>(LEAD + STEP);
  return (
    <Tile area="speed" dark>
      <div ref={ref} className="vb-stat">
        <span className="vb-stat-lead">A claim proves in about</span>
        <span className="vb-stat-number">
          <Count
            value={seen || reduced ? 2 : 9}
            format={(n) => (Math.round(n) / 10).toFixed(1)}
            duration={1100}
          />
          <span className="vb-stat-unit"> s</span>
        </span>
        <span className="vb-stat-label">on an iPhone, with the passport nowhere near.</span>
      </div>
    </Tile>
  );
}

function Chain() {
  return (
    <Tile
      area="chain"
      drift={40}
      lead="Checkable on Solana."
      picture={
        <span className="vb-foot">
          <span>Groth16</span>
          <span>BN254</span>
        </span>
      }
    >
      Anyone can check a proof off-chain. A program can check one on-chain, so other programs can
      condition on it.
    </Tile>
  );
}

const CHECKS = [
  'Data group hashes',
  'Document signature',
  'Chain to the issuing state',
  'Chip signs a challenge',
];

function Verify() {
  const [picture, width] = usePictureWidth();
  return (
    <Tile
      area="verify"
      drift={72}
      lead="Checks the state’s signatures."
      picture={
        <div ref={picture} className="vb-picture" aria-hidden>
          {width > 0 && (
            <Stage<Beat>
              width={width}
              height={286}
              initial={before}
              poster={after}
              play="once"
              script={scripts[3]}
              className="vb-stage"
            >
              {(scene) => (
                <div className="vb-panel vb-checks" data-on={on(scene.on)}>
                  {CHECKS.map((label) => (
                    <Row key={label} title={<span className="vb-name">{label}</span>} pad={14}>
                      <Check on={scene.on} size={22} />
                    </Row>
                  ))}
                </div>
              )}
            </Stage>
          )}
        </div>
      }
    >
      Before it proves anything, Passport verifies the document the way a border gate does.
    </Tile>
  );
}

const SPEAKS = ['BAC', 'Secure messaging', 'DG1', 'DG2', 'EF.SOD', 'Active Authentication'];

function Readers() {
  return (
    <Tile
      area="readers"
      drift={40}
      lead="iPhone or Flipper Zero."
      picture={
        <span className="vb-foot vb-foot--wrap">
          {SPEAKS.map((label) => (
            <span key={label}>{label}</span>
          ))}
        </span>
      }
    >
      One reader runs on both, speaking ICAO 9303 over NFC.
    </Tile>
  );
}

function Ask() {
  const [picture, width] = usePictureWidth();
  return (
    <Tile
      area="ask"
      drift={72}
      lead="For websites, apps and agents."
      picture={
        <div ref={picture} className="vb-picture" aria-hidden>
          {width > 0 && (
            <Stage width={width} height={176} className="vb-stage">
              {() => (
                <div className="vb-panel vb-request">
                  <code>openid4vp://?request_uri=…</code>
                  <span className="vb-claims">
                    <span>age.gte(18)</span>
                    <span>nationality</span>
                  </span>
                </div>
              )}
            </Stage>
          )}
        </div>
      }
    >
      A request is an OpenID4VP link and a few claims.
    </Tile>
  );
}

/** The features grid: six tiles of three sizes. */
export function Bento() {
  return (
    <div className="vb">
      <div className="vb-grid">
        <Private />
        <Speed />
        <Chain />
        <Verify />
        <Readers />
        <Ask />
      </div>
    </div>
  );
}
