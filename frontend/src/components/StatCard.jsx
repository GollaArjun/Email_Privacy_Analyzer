import React from 'react';

const StatCard = ({ title, value, subtitle, icon: Icon, color = 'cyan', alert = false }) => {
  const colorMap = {
    cyan: {
      text: 'text-cyan-400',
      bg: 'bg-cyan-500/10',
      border: 'border-cyan-500/20',
      glow: 'hover:shadow-cyan-500/10',
    },
    emerald: {
      text: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
      glow: 'hover:shadow-emerald-500/10',
    },
    amber: {
      text: 'text-amber-400',
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/20',
      glow: 'hover:shadow-amber-500/10',
    },
    red: {
      text: 'text-red-400',
      bg: 'bg-red-500/10',
      border: 'border-red-500/30',
      glow: 'hover:shadow-red-500/20',
    },
    blue: {
      text: 'text-blue-400',
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/20',
      glow: 'hover:shadow-blue-500/10',
    },
  };

  const scheme = colorMap[color] || colorMap.cyan;

  return (
    <div
      className={`glass-panel p-5 relative overflow-hidden transition-all duration-200 border ${scheme.border} ${scheme.glow} hover:border-slate-600`}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400 mb-1">
            {title}
          </p>
          <h3 className="text-2xl font-bold font-mono tracking-tight text-white">
            {value}
          </h3>
          {subtitle && (
            <p className="text-xs text-slate-400 mt-1 flex items-center gap-1">
              {subtitle}
            </p>
          )}
        </div>
        {Icon && (
          <div className={`p-2.5 rounded-lg border ${scheme.border} ${scheme.bg} ${scheme.text}`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>

      {alert && (
        <div className="absolute top-0 right-0 w-2 h-2 rounded-full bg-red-500 animate-ping m-2" />
      )}
    </div>
  );
};

export default StatCard;
