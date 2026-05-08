import { useCallback, useEffect, useRef, useState } from "react";
import { gsap } from "gsap";
import "./MagicBento.css";

const DEFAULT_PARTICLE_COUNT = 12;
const DEFAULT_SPOTLIGHT_RADIUS = 300;
const DEFAULT_GLOW_COLOR = "132, 0, 255";
const MOBILE_BREAKPOINT = 768;

const defaultCards = [
  {
    title: "CIS Benchmark",
    description: "Container hardening, runtime user, health checks, and privilege posture.",
    label: "Compliance"
  },
  {
    title: "Secrets",
    description: "Detects exposed tokens, keys, credentials, and high entropy material.",
    label: "Detection"
  },
  {
    title: "Supply Chain",
    description: "Tracks provenance gaps, mutable tags, and risky startup commands.",
    label: "Integrity"
  },
  {
    title: "Runtime",
    description: "Reviews privileged mode, host namespaces, networking, and mounts.",
    label: "Behavior"
  },
  {
    title: "Vulnerabilities",
    description: "Normalizes image CVEs into one review and reporting stream.",
    label: "Exposure"
  },
  {
    title: "Reports",
    description: "Exports security evidence and remediation context for review.",
    label: "Evidence"
  }
];

function createParticleElement(x, y, color = DEFAULT_GLOW_COLOR) {
  const element = document.createElement("div");
  element.className = "magic-bento-particle";
  element.style.cssText = `
    left: ${x}px;
    top: ${y}px;
    background: rgba(${color}, 1);
    box-shadow: 0 0 6px rgba(${color}, 0.6);
  `;
  return element;
}

function calculateSpotlightValues(radius) {
  return {
    proximity: radius * 0.5,
    fadeDistance: radius * 0.75
  };
}

function updateCardGlowProperties(card, mouseX, mouseY, glow, radius) {
  const rect = card.getBoundingClientRect();
  const relativeX = ((mouseX - rect.left) / rect.width) * 100;
  const relativeY = ((mouseY - rect.top) / rect.height) * 100;

  card.style.setProperty("--magic-glow-x", `${relativeX}%`);
  card.style.setProperty("--magic-glow-y", `${relativeY}%`);
  card.style.setProperty("--magic-glow-intensity", glow.toString());
  card.style.setProperty("--magic-glow-radius", `${radius}px`);
}

function useMobileDetection() {
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    function checkMobile() {
      setIsMobile(window.innerWidth <= MOBILE_BREAKPOINT);
    }

    checkMobile();
    window.addEventListener("resize", checkMobile);
    return () => window.removeEventListener("resize", checkMobile);
  }, []);

  return isMobile;
}

function ParticleCard({
  children,
  className = "",
  disableAnimations = false,
  style,
  particleCount = DEFAULT_PARTICLE_COUNT,
  glowColor = DEFAULT_GLOW_COLOR,
  enableTilt = true,
  clickEffect = false,
  enableMagnetism = false
}) {
  const cardRef = useRef(null);
  const particlesRef = useRef([]);
  const timeoutsRef = useRef([]);
  const isHoveredRef = useRef(false);
  const memoizedParticles = useRef([]);
  const particlesInitialized = useRef(false);
  const magnetismAnimationRef = useRef(null);

  const initializeParticles = useCallback(() => {
    if (particlesInitialized.current || !cardRef.current) {
      return;
    }

    const { width, height } = cardRef.current.getBoundingClientRect();
    memoizedParticles.current = Array.from({ length: particleCount }, () =>
      createParticleElement(Math.random() * width, Math.random() * height, glowColor)
    );
    particlesInitialized.current = true;
  }, [particleCount, glowColor]);

  const clearAllParticles = useCallback(() => {
    timeoutsRef.current.forEach(clearTimeout);
    timeoutsRef.current = [];
    magnetismAnimationRef.current?.kill();

    particlesRef.current.forEach((particle) => {
      gsap.to(particle, {
        scale: 0,
        opacity: 0,
        duration: 0.3,
        ease: "back.in(1.7)",
        onComplete: () => particle.parentNode?.removeChild(particle)
      });
    });
    particlesRef.current = [];
  }, []);

  const animateParticles = useCallback(() => {
    if (!cardRef.current || !isHoveredRef.current) {
      return;
    }

    if (!particlesInitialized.current) {
      initializeParticles();
    }

    memoizedParticles.current.forEach((particle, index) => {
      const timeoutId = setTimeout(() => {
        if (!isHoveredRef.current || !cardRef.current) {
          return;
        }

        const clone = particle.cloneNode(true);
        cardRef.current.appendChild(clone);
        particlesRef.current.push(clone);

        gsap.fromTo(clone, { scale: 0, opacity: 0 }, { scale: 1, opacity: 1, duration: 0.3, ease: "back.out(1.7)" });
        gsap.to(clone, {
          x: (Math.random() - 0.5) * 100,
          y: (Math.random() - 0.5) * 100,
          rotation: Math.random() * 360,
          duration: 2 + Math.random() * 2,
          ease: "none",
          repeat: -1,
          yoyo: true
        });
        gsap.to(clone, {
          opacity: 0.3,
          duration: 1.5,
          ease: "power2.inOut",
          repeat: -1,
          yoyo: true
        });
      }, index * 100);

      timeoutsRef.current.push(timeoutId);
    });
  }, [initializeParticles]);

  useEffect(() => {
    if (disableAnimations || !cardRef.current) {
      return undefined;
    }

    const element = cardRef.current;

    function handleMouseEnter() {
      isHoveredRef.current = true;
      animateParticles();

      if (enableTilt) {
        gsap.to(element, {
          rotateX: 5,
          rotateY: 5,
          duration: 0.3,
          ease: "power2.out",
          transformPerspective: 1000
        });
      }
    }

    function handleMouseLeave() {
      isHoveredRef.current = false;
      clearAllParticles();

      if (enableTilt) {
        gsap.to(element, {
          rotateX: 0,
          rotateY: 0,
          duration: 0.3,
          ease: "power2.out"
        });
      }

      if (enableMagnetism) {
        gsap.to(element, {
          x: 0,
          y: 0,
          duration: 0.3,
          ease: "power2.out"
        });
      }
    }

    function handleMouseMove(event) {
      if (!enableTilt && !enableMagnetism) {
        return;
      }

      const rect = element.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      const centerX = rect.width / 2;
      const centerY = rect.height / 2;

      if (enableTilt) {
        gsap.to(element, {
          rotateX: ((y - centerY) / centerY) * -10,
          rotateY: ((x - centerX) / centerX) * 10,
          duration: 0.1,
          ease: "power2.out",
          transformPerspective: 1000
        });
      }

      if (enableMagnetism) {
        magnetismAnimationRef.current = gsap.to(element, {
          x: (x - centerX) * 0.05,
          y: (y - centerY) * 0.05,
          duration: 0.3,
          ease: "power2.out"
        });
      }
    }

    function handleClick(event) {
      if (!clickEffect) {
        return;
      }

      const rect = element.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      const maxDistance = Math.max(
        Math.hypot(x, y),
        Math.hypot(x - rect.width, y),
        Math.hypot(x, y - rect.height),
        Math.hypot(x - rect.width, y - rect.height)
      );

      const ripple = document.createElement("div");
      ripple.className = "magic-bento-ripple";
      ripple.style.cssText = `
        width: ${maxDistance * 2}px;
        height: ${maxDistance * 2}px;
        left: ${x - maxDistance}px;
        top: ${y - maxDistance}px;
        background: radial-gradient(circle, rgba(${glowColor}, 0.4) 0%, rgba(${glowColor}, 0.2) 30%, transparent 70%);
      `;

      element.appendChild(ripple);
      gsap.fromTo(ripple, { scale: 0, opacity: 1 }, { scale: 1, opacity: 0, duration: 0.8, ease: "power2.out", onComplete: () => ripple.remove() });
    }

    element.addEventListener("mouseenter", handleMouseEnter);
    element.addEventListener("mouseleave", handleMouseLeave);
    element.addEventListener("mousemove", handleMouseMove);
    element.addEventListener("click", handleClick);

    return () => {
      isHoveredRef.current = false;
      element.removeEventListener("mouseenter", handleMouseEnter);
      element.removeEventListener("mouseleave", handleMouseLeave);
      element.removeEventListener("mousemove", handleMouseMove);
      element.removeEventListener("click", handleClick);
      clearAllParticles();
    };
  }, [animateParticles, clearAllParticles, disableAnimations, enableTilt, enableMagnetism, clickEffect, glowColor]);

  return (
    <div ref={cardRef} className={`${className} magic-bento-particle-container`} style={style}>
      {children}
    </div>
  );
}

function GlobalSpotlight({
  gridRef,
  disableAnimations = false,
  enabled = true,
  spotlightRadius = DEFAULT_SPOTLIGHT_RADIUS,
  glowColor = DEFAULT_GLOW_COLOR
}) {
  const spotlightRef = useRef(null);

  useEffect(() => {
    if (disableAnimations || !gridRef?.current || !enabled) {
      return undefined;
    }

    const spotlight = document.createElement("div");
    spotlight.className = "magic-bento-global-spotlight";
    spotlight.style.setProperty("--magic-spotlight-color", glowColor);
    document.body.appendChild(spotlight);
    spotlightRef.current = spotlight;

    function handleMouseMove(event) {
      if (!spotlightRef.current || !gridRef.current) {
        return;
      }

      const section = gridRef.current.closest(".magic-bento-section");
      const rect = section?.getBoundingClientRect();
      const mouseInside =
        rect && event.clientX >= rect.left && event.clientX <= rect.right && event.clientY >= rect.top && event.clientY <= rect.bottom;
      const cards = gridRef.current.querySelectorAll(".magic-bento-card");

      if (!mouseInside) {
        gsap.to(spotlightRef.current, { opacity: 0, duration: 0.3, ease: "power2.out" });
        cards.forEach((card) => card.style.setProperty("--magic-glow-intensity", "0"));
        return;
      }

      const { proximity, fadeDistance } = calculateSpotlightValues(spotlightRadius);
      let minDistance = Infinity;

      cards.forEach((card) => {
        const cardRect = card.getBoundingClientRect();
        const centerX = cardRect.left + cardRect.width / 2;
        const centerY = cardRect.top + cardRect.height / 2;
        const distance = Math.hypot(event.clientX - centerX, event.clientY - centerY) - Math.max(cardRect.width, cardRect.height) / 2;
        const effectiveDistance = Math.max(0, distance);
        minDistance = Math.min(minDistance, effectiveDistance);

        let glowIntensity = 0;
        if (effectiveDistance <= proximity) {
          glowIntensity = 1;
        } else if (effectiveDistance <= fadeDistance) {
          glowIntensity = (fadeDistance - effectiveDistance) / (fadeDistance - proximity);
        }

        updateCardGlowProperties(card, event.clientX, event.clientY, glowIntensity, spotlightRadius);
      });

      gsap.to(spotlightRef.current, {
        left: event.clientX,
        top: event.clientY,
        duration: 0.1,
        ease: "power2.out"
      });

      const targetOpacity =
        minDistance <= proximity
          ? 0.8
          : minDistance <= fadeDistance
            ? ((fadeDistance - minDistance) / (fadeDistance - proximity)) * 0.8
            : 0;

      gsap.to(spotlightRef.current, {
        opacity: targetOpacity,
        duration: targetOpacity > 0 ? 0.2 : 0.5,
        ease: "power2.out"
      });
    }

    function handleMouseLeave() {
      gridRef.current?.querySelectorAll(".magic-bento-card").forEach((card) => {
        card.style.setProperty("--magic-glow-intensity", "0");
      });
      if (spotlightRef.current) {
        gsap.to(spotlightRef.current, { opacity: 0, duration: 0.3, ease: "power2.out" });
      }
    }

    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseleave", handleMouseLeave);

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseleave", handleMouseLeave);
      spotlightRef.current?.parentNode?.removeChild(spotlightRef.current);
    };
  }, [gridRef, disableAnimations, enabled, spotlightRadius, glowColor]);

  return null;
}

export default function MagicBento({
  cards = defaultCards,
  textAutoHide = true,
  enableStars = true,
  enableSpotlight = true,
  enableBorderGlow = true,
  disableAnimations = false,
  spotlightRadius = DEFAULT_SPOTLIGHT_RADIUS,
  particleCount = DEFAULT_PARTICLE_COUNT,
  enableTilt = false,
  glowColor = DEFAULT_GLOW_COLOR,
  clickEffect = true,
  enableMagnetism = true
}) {
  const gridRef = useRef(null);
  const isMobile = useMobileDetection();
  const shouldDisableAnimations = disableAnimations || isMobile;

  return (
    <>
      {enableSpotlight ? (
        <GlobalSpotlight
          gridRef={gridRef}
          disableAnimations={shouldDisableAnimations}
          enabled={enableSpotlight}
          spotlightRadius={spotlightRadius}
          glowColor={glowColor}
        />
      ) : null}

      <div className="magic-bento-grid magic-bento-section" ref={gridRef}>
        {cards.map((card, index) => (
          <ParticleCard
            key={`${card.title}-${index}`}
            className={`magic-bento-card ${textAutoHide ? "magic-bento-card--text-autohide" : ""} ${enableBorderGlow ? "magic-bento-card--border-glow" : ""}`}
            style={{
              backgroundColor: card.color || "#120F17",
              "--magic-glow-color": glowColor
            }}
            disableAnimations={shouldDisableAnimations || !enableStars}
            particleCount={particleCount}
            glowColor={glowColor}
            enableTilt={enableTilt}
            clickEffect={clickEffect}
            enableMagnetism={enableMagnetism}
          >
            <div className="magic-bento-card__header">
              <div className="magic-bento-card__label">{card.label}</div>
              {card.count !== undefined ? <strong>{card.count}</strong> : null}
            </div>
            <div className="magic-bento-card__content">
              <h2 className="magic-bento-card__title">{card.title}</h2>
              <p className="magic-bento-card__description">{card.description}</p>
            </div>
          </ParticleCard>
        ))}
      </div>
    </>
  );
}
