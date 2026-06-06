// Bhairab brand marks — the guardian eye + wordmark.
// The eye's iris doubles as a network hub: the watchful guardian over a
// decentralized network. Minimal, sigil-like, etched-on-obsidian.

export function EyeMark({ size = 28, className = "" }: { size?: number; className?: string }) {
  // The guardian's eye over a radial network: a bold double-stroke almond eye,
  // two concentric rings, 8-spoke node web, and a crimson core. The bold eye +
  // core dominate so it degrades gracefully to favicon size; the network recedes.
  const C = 50, rIn = 17, rOut = 34;
  const dirs = Array.from({ length: 8 }, (_, i) => -Math.PI / 2 + (i * Math.PI) / 4);
  const pt = (r: number, a: number) => ({
    x: +(C + r * Math.cos(a)).toFixed(2),
    y: +(C + r * Math.sin(a)).toFixed(2),
  });
  const inner = dirs.map((a) => pt(rIn, a));
  const outer = dirs.map((a) => pt(rOut, a));

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      fill="none"
      className={className}
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      {/* concentric guide rings */}
      <circle cx={C} cy={C} r={rOut} stroke="#ECECEC" strokeWidth="0.8" opacity="0.32" />
      <circle cx={C} cy={C} r={rIn} stroke="#ECECEC" strokeWidth="0.9" opacity="0.5" />
      {/* 4 diameters through the hub */}
      <g stroke="#ECECEC" strokeWidth="0.8" opacity="0.4">
        {[0, 1, 2, 3].map((i) => (
          <line key={i} x1={outer[i].x} y1={outer[i].y} x2={outer[i + 4].x} y2={outer[i + 4].y} />
        ))}
      </g>
      {/* outer nodes */}
      <g stroke="#ECECEC" strokeWidth="1" fill="#0A0A0B">
        {outer.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="2.4" />
        ))}
      </g>
      {/* inner nodes */}
      <g stroke="#ECECEC" strokeWidth="1" fill="#0A0A0B" opacity="0.9">
        {inner.map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="1.9" />
        ))}
      </g>
      {/* almond eye — bold double stroke */}
      <g stroke="#ECECEC" fill="none" strokeLinejoin="round">
        <path d="M6 50 C 27 19, 73 19, 94 50 C 73 81, 27 81, 6 50 Z" strokeWidth="2.4" />
        <path d="M14 50 C 31 27, 69 27, 86 50 C 69 73, 31 73, 14 50 Z" strokeWidth="0.9" opacity="0.7" />
      </g>
      {/* crimson core */}
      <circle cx={C} cy={C} r="9.5" fill="#0A0A0B" stroke="#ECECEC" strokeWidth="1.4" />
      <circle cx={C} cy={C} r="6" fill="#E5392B" />
    </svg>
  );
}

export function Wordmark({ className = "" }: { className?: string }) {
  return (
    <span className={`font-semibold tracking-[0.22em] text-[#ECECEC] ${className}`}>
      BHAIRAB
    </span>
  );
}

export function Logo() {
  // Wordmark only in nav — the detailed eye mark reads muddy at small sizes.
  // The eye lives in the hero, favicon, and decorative spots instead.
  return <Wordmark className="text-sm" />;
}
