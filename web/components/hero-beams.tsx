"use client";

import { useEffect, useRef } from "react";

// Animated crimson beams that undulate outward from the guardian eye — energy
// streaming from the hub into the decentralized network. Sits behind the eye.
export function HeroBeams() {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const W = canvas.clientWidth;
    const H = canvas.clientHeight;
    canvas.width = W * dpr;
    canvas.height = H * dpr;
    ctx.scale(dpr, dpr);
    const cx = W / 2;
    const cy = H / 2;

    // Mostly-horizontal beams (the eye looks out sideways), with a few diagonals.
    const degs = [-10, 8, 170, 190, 32, -36, 150, -148];
    const beams = degs.map((d) => ({
      angle: (d * Math.PI) / 180,
      len: 240 + Math.random() * 200,
      amp: 12 + Math.random() * 16,
      freq: 0.011 + Math.random() * 0.01,
      phase: Math.random() * Math.PI * 2,
      speed: 0.5 + Math.random() * 0.5,
      width: 1.3 + Math.random() * 1.1,
    }));

    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const start = performance.now();
    let raf = 0;

    function drawBeam(b: (typeof beams)[number], t: number) {
      const dx = Math.cos(b.angle), dy = Math.sin(b.angle);
      const nx = -dy, ny = dx; // unit normal for the wave offset
      const ex = cx + dx * b.len, ey = cy + dy * b.len;
      const grad = ctx!.createLinearGradient(cx, cy, ex, ey);
      grad.addColorStop(0, "rgba(229,57,43,0)");      // emerges from the eye
      grad.addColorStop(0.12, "rgba(229,57,43,0.55)");
      grad.addColorStop(1, "rgba(229,57,43,0)");       // dissolves into the dark

      const trace = () => {
        ctx!.beginPath();
        const steps = 44;
        for (let s = 0; s <= steps; s++) {
          const f = s / steps;
          const dist = 22 + f * b.len; // start just outside the eye
          const env = Math.sin(f * Math.PI); // taper at both ends
          const off = Math.sin(dist * b.freq + t * b.speed + b.phase) * b.amp * env;
          const x = cx + dx * dist + nx * off;
          const y = cy + dy * dist + ny * off;
          s === 0 ? ctx!.moveTo(x, y) : ctx!.lineTo(x, y);
        }
      };

      // glow halo
      ctx!.strokeStyle = grad;
      ctx!.globalAlpha = 0.25;
      ctx!.lineWidth = b.width * 4;
      trace();
      ctx!.stroke();
      // bright core
      ctx!.globalAlpha = 1;
      ctx!.lineWidth = b.width;
      trace();
      ctx!.stroke();
    }

    function frame(now: number) {
      const t = (now - start) / 1000;
      ctx!.clearRect(0, 0, W, H);
      ctx!.globalCompositeOperation = "lighter";
      ctx!.lineCap = "round";
      for (const b of beams) drawBeam(b, t);
      ctx!.globalCompositeOperation = "source-over";
      ctx!.globalAlpha = 1;
      if (!reduce) raf = requestAnimationFrame(frame);
    }

    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, []);

  return (
    <canvas
      ref={ref}
      aria-hidden="true"
      className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none z-0"
      style={{ width: 920, height: 300, maxWidth: "100vw" }}
    />
  );
}
