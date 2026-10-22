import React from 'react';
import { Check } from 'lucide-react';

export type StageState = 'idle' | 'active' | 'done';

type StageProps = {
  id: string;
  n: number;
  title: string;
  hint?: string;
  state?: StageState;
  children: React.ReactNode;
};

/**
 * A single step of the progressive flow: numbered marker on a vertical rail
 * plus the stage body. The marker changes with the stage state.
 */
export const Stage: React.FC<StageProps> = ({ id, n, title, hint, state = 'idle', children }) => (
  <section className="stage" id={id} data-state={state}>
    <div className="stage__rail" aria-hidden="true">
      <span className="stage__num">
        {state === 'done' ? <Check style={{ width: 13, height: 13 }} /> : <span className="mono">{n}</span>}
      </span>
      <span className="stage__line" />
    </div>
    <div className="stage__body">
      <div className="stage__head">
        <h2 className="stage__title">{title}</h2>
        {hint && <span className="stage__hint">{hint}</span>}
      </div>
      {children}
    </div>
  </section>
);

type StageStep = {
  id: string;
  label: string;
  state: StageState;
};

type StageNavProps = {
  steps: StageStep[];
  onJump: (id: string) => void;
};

/**
 * Compact horizontal progress strip — shows what the flow produces next.
 */
export const StageNav: React.FC<StageNavProps> = ({ steps, onJump }) => (
  <nav className="progress" aria-label="مراحل کار">
    {steps.map((s, i) => (
      <div className="progress__group" key={s.id}>
        <button
          type="button"
          className={`progress__step ${s.state === 'active' ? 'is-active' : ''} ${s.state === 'done' ? 'is-done' : ''}`}
          onClick={() => onJump(s.id)}
        >
          <span className="progress__dot">
            {s.state === 'done' ? <Check style={{ width: 10, height: 10 }} /> : <span className="mono">{i + 1}</span>}
          </span>
          <span className="progress__label">{s.label}</span>
        </button>
        {i < steps.length - 1 && <span className="progress__link" />}
      </div>
    ))}
  </nav>
);
