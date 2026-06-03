// Bhairab brand marks — the guardian eye + wordmark.
// The eye's iris doubles as a network hub: the watchful guardian over a
// decentralized network. Minimal, sigil-like, etched-on-obsidian.

export function EyeMark({ size = 28, className = "" }: { size?: number; className?: string }) {
  // 8 network nodes evenly on the iris ring — the decentralized network the
  // guardian watches over. Symmetric, contained, no external "legs".
  const cx = 24, cy = 24, ring = 9;
  const nodes = Array.from({ length: 8 }, (_, i) => {
    const a = (Math.PI / 4) * i - Math.PI / 2;
    return { x: cx + ring * Math.cos(a), y: cy + ring * Math.sin(a) };
  });
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      className={className}
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      {/* almond eye — the guardian's gaze */}
      <path
        d="M2 24C11 12 37 12 46 24C37 36 11 36 2 24Z"
        stroke="#ECECEC"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      {/* iris ring */}
      <circle cx={cx} cy={cy} r={ring} stroke="#ECECEC" strokeWidth="1.4" />
      {/* network nodes on the ring */}
      <g fill="#8A8A8F">
        {nodes.map((n, i) => (
          <circle key={i} cx={n.x} cy={n.y} r="1.15" />
        ))}
      </g>
      {/* crimson core — Bhairab */}
      <circle cx={cx} cy={cy} r="3.6" fill="#E5392B" />
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

export function Logo({ size = 26 }: { size?: number }) {
  return (
    <div className="flex items-center gap-2.5">
      <EyeMark size={size} />
      <Wordmark className="text-sm" />
    </div>
  );
}
