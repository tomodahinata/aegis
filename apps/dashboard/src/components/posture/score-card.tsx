import type { PostureScore } from '@aegiskit/observability';
import { Shield, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { type GradeIcon, gradeToVisual, type Tone } from '@/lib/posture/grade-ui';

const ICON: Record<GradeIcon, typeof ShieldCheck> = {
  'shield-check': ShieldCheck,
  shield: Shield,
  'shield-alert': ShieldAlert,
  'shield-x': ShieldX,
};

const TONE_TEXT: Record<Tone, string> = {
  good: 'text-tone-good',
  ok: 'text-tone-ok',
  warn: 'text-tone-warn',
  bad: 'text-tone-bad',
};

export function ScoreCard({ posture }: { posture: PostureScore }) {
  const visual = gradeToVisual(posture.grade);
  const Icon = ICON[visual.icon];
  return (
    <Card>
      <h2 className="text-sm font-medium text-muted">Posture score</h2>
      <div className="mt-2 flex items-baseline gap-3">
        <span className="font-bold text-4xl tabular-nums">{posture.score}</span>
        <span
          className={`inline-flex items-center gap-1.5 font-semibold text-lg ${TONE_TEXT[visual.tone]}`}
        >
          <Icon className="size-5" aria-hidden="true" />
          <span>
            Grade {posture.grade} — {visual.label}
          </span>
        </span>
      </div>
      <p className="mt-2 text-muted text-sm">
        Lower volume of high-severity events keeps this higher. Recent activity weighs most.
      </p>
    </Card>
  );
}
