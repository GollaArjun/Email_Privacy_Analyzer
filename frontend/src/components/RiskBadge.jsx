import React from 'react';

const RiskBadge = ({ level = 'Low', size = 'md' }) => {
  const norm = (level || 'Low').toLowerCase();

  const configs = {
    low: {
      bg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
      dot: 'bg-emerald-400 shadow-emerald-400/50',
      label: 'Low Risk',
    },
    moderate: {
      bg: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
      dot: 'bg-blue-400 shadow-blue-400/50',
      label: 'Moderate Risk',
    },
    medium: {
      bg: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
      dot: 'bg-yellow-400 shadow-yellow-400/50',
      label: 'Medium Risk',
    },
    high: {
      bg: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
      dot: 'bg-amber-400 shadow-amber-400/50',
      label: 'High Risk',
    },
    'very high': {
      bg: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
      dot: 'bg-orange-400 shadow-orange-400/50',
      label: 'Very High Risk',
    },
    critical: {
      bg: 'bg-red-500/15 text-red-400 border-red-500/40 animate-pulse',
      dot: 'bg-red-400 shadow-red-400/80',
      label: 'Critical Threat',
    },
  };

  const current = configs[norm] || configs.low;

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-xs px-2.5 py-1 font-medium',
    lg: 'text-sm px-3.5 py-1.5 font-semibold',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border ${current.bg} ${sizeClasses[size] || sizeClasses.md}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${current.dot} shadow-sm`} />
      {current.label}
    </span>
  );
};

export default RiskBadge;
