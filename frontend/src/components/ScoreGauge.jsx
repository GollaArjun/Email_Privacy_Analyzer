import React from 'react';

const ScoreGauge = ({ score = 0, category = 'Low', size = 200 }) => {
  const clampedScore = Math.min(Math.max(score, 0), 100);

  // SVG Gauge calculations (semi-circle)
  const radius = 80;
  const strokeWidth = 14;
  const circumference = Math.PI * radius; // Half-circle perimeter
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  const getColor = (s) => {
    if (s >= 80) return '#EF4444'; // Red
    if (s >= 60) return '#F97316'; // Orange
    if (s >= 40) return '#EAB308'; // Amber
    if (s >= 20) return '#3B82F6'; // Blue
    return '#10B981'; // Emerald
  };

  const currentColor = getColor(clampedScore);

  return (
    <div className="flex flex-col items-center justify-center relative">
      <svg
        width={size}
        height={size * 0.65}
        viewBox="0 0 200 130"
        className="overflow-visible"
      >
        <defs>
          <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#10B981" />
            <stop offset="35%" stopColor="#3B82F6" />
            <stop offset="65%" stopColor="#EAB308" />
            <stop offset="85%" stopColor="#F97316" />
            <stop offset="100%" stopColor="#EF4444" />
          </linearGradient>
          <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="glow" />
            <feComposite in="SourceGraphic" in2="glow" operator="over" />
          </filter>
        </defs>

        {/* Background Track */}
        <path
          d="M 20 110 A 80 80 0 0 1 180 110"
          fill="none"
          stroke="#1F293D"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />

        {/* Animated Meter Progress Track */}
        <path
          d="M 20 110 A 80 80 0 0 1 180 110"
          fill="none"
          stroke={currentColor}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          filter="url(#glow)"
          className="transition-all duration-1000 ease-out"
        />

        {/* Central Display */}
        <text
          x="100"
          y="90"
          textAnchor="middle"
          fill="#F8FAFC"
          fontSize="36"
          fontWeight="bold"
          fontFamily="monospace"
        >
          {clampedScore}
        </text>
        <text
          x="100"
          y="110"
          textAnchor="middle"
          fill="#94A3B8"
          fontSize="11"
          fontWeight="medium"
          letterSpacing="0.05em"
        >
          RISK INDEX / 100
        </text>
      </svg>

      <div
        className="mt-1 text-xs font-semibold uppercase tracking-wider px-3 py-0.5 rounded-full border border-slate-700/60"
        style={{ color: currentColor, backgroundColor: `${currentColor}15` }}
      >
        {category} Risk
      </div>
    </div>
  );
};

export default ScoreGauge;
