/* ==========================================================================
   TrustLens - main frontend behaviour
   Particles, navbar scroll, scroll-reveal, counters, result gauges and the
   shared API helper used by every scanner page.
   ========================================================================== */

(function () {
  "use strict";

  /* ---- Navbar scrolled state ------------------------------------------- */
  function onScroll() {
    const nav = document.querySelector(".navbar-trust");
    if (nav) nav.classList.toggle("scrolled", window.scrollY > 24);
  }
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  /* ---- Auto-dismiss flash alerts --------------------------------------- */
  document.querySelectorAll(".alert-trust").forEach(function (alert) {
    setTimeout(function () {
      alert.style.transition = "opacity .5s ease";
      alert.style.opacity = "0";
      setTimeout(function () { alert.remove(); }, 550);
    }, 4200);
  });

  /* ---- Scroll reveal ---------------------------------------------------- */
  const revealEls = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("visible");
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    revealEls.forEach(function (el) { io.observe(el); });
  } else {
    revealEls.forEach(function (el) { el.classList.add("visible"); });
  }

  /* ---- Animated counters ----------------------------------------------- */
  function animateCount(el) {
    const target = parseFloat(el.dataset.count || "0");
    const decimals = (el.dataset.count || "").includes(".") ? 1 : 0;
    const duration = 1200;
    const start = performance.now();
    function tick(now) {
      const p = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = (target * eased).toFixed(decimals);
      if (p < 1) requestAnimationFrame(tick);
      else el.textContent = target.toFixed(decimals);
    }
    requestAnimationFrame(tick);
  }

  const counters = document.querySelectorAll("[data-count]");
  if (counters.length && "IntersectionObserver" in window) {
    const cio = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          animateCount(entry.target);
          cio.unobserve(entry.target);
        }
      });
    }, { threshold: 0.5 });
    counters.forEach(function (el) { cio.observe(el); });
  }

  /* ---- Shared API helper ------------------------------------------------ */
  window.TrustLens = {
    apiPost: function (url, data, isFormData) {
      const opts = { method: "POST", headers: { "X-Requested-With": "XMLHttpRequest" } };
      if (isFormData) {
        opts.body = data; // FormData sets its own multipart content-type
      } else {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(data);
      }
      return fetch(url, opts).then(function (res) {
        return res.json().then(function (json) {
          if (!res.ok || json.success === false) {
            const err = new Error(json.error || "Request failed.");
            err.status = res.status;
            throw err;
          }
          return json;
        });
      });
    },

    showError: function (box, message) {
      if (!box) return;
      box.innerHTML = "";
      box.classList.remove("result-hidden");
      box.classList.add("glass", "p-4");
      box.innerHTML =
        '<div class="d-flex align-items-start gap-3">' +
        '<span style="font-size:1.6rem;color:var(--red)">&#9888;</span>' +
        '<div><h5 class="mb-1" style="color:var(--red)">Scan error</h5>' +
        '<p class="text-muted-c mb-0">' + escapeHtml(message) + "</p></div></div>";
      box.scrollIntoView({ behavior: "smooth", block: "nearest" });
    },

    loading: function (btn, text) {
      btn.disabled = true;
      const original = btn.dataset.original || btn.innerHTML;
      btn.dataset.original = original;
      btn.innerHTML =
        '<span class="spin-orb"></span> ' + (text || "Scanning...");
      return btn;
    },

    doneLoading: function (btn) {
      btn.disabled = false;
      if (btn.dataset.original) btn.innerHTML = btn.dataset.original;
    },

    /* Build a circular trust gauge. score 0-100 */
    renderGauge: function (container, score) {
      const ring = document.createElement("div");
      ring.className = "gauge-ring";
      const color =
        score >= 70 ? "var(--green)" : score >= 45 ? "var(--yellow)" : "var(--red)";
      ring.style.setProperty("--ring-color", color);
      ring.style.setProperty("--value", score);
      ring.innerHTML =
        '<div class="gauge-inner">' +
        '<div class="gauge-num">' + score + '</div>' +
        '<div class="gauge-label">TRUST SCORE</div></div>';
      container.innerHTML = "";
      container.appendChild(ring);
    },

    /* Risk gauge for the email scanner - higher score = MORE dangerous.
       Colour semantics are the inverse of the trust gauge above. */
    renderRiskGauge: function (container, score, label) {
      const ring = document.createElement("div");
      ring.className = "gauge-ring gauge-risk";
      const color =
        score >= 70 ? "var(--red)" : score >= 45 ? "var(--yellow)" : "var(--green)";
      ring.style.setProperty("--ring-color", color);
      ring.style.setProperty("--value", score);
      ring.innerHTML =
        '<div class="gauge-inner">' +
        '<div class="gauge-num">' + score + '</div>' +
        '<div class="gauge-label">' + (label || "RISK SCORE") + '</div></div>';
      container.innerHTML = "";
      container.appendChild(ring);
    },

    /* Status pill carrying a human-readable risk label + emoji, e.g. "Suspicious". */
    renderRiskPill: function (status, label, emoji) {
      const cls =
        status === "safe" ? "badge-safe" : status === "warning" ? "badge-warning" : "badge-dangerous";
      return '<span class="status-pill ' + cls + '">' +
        (emoji ? emoji + " " : "") + escapeHtml(label || (status || "").toUpperCase()) +
        "</span>";
    },

    renderStatusPill: function (status) {
      const labels = { safe: "SAFE", warning: "WARNING", dangerous: "DANGEROUS" };
      const cls =
        status === "safe" ? "badge-safe" : status === "warning" ? "badge-warning" : "badge-dangerous";
      return '<span class="status-pill ' + cls + '">' + (labels[status] || status.toUpperCase()) + "</span>";
    },

    renderReasons: function (list, reasons) {
      list.innerHTML = "";
      (reasons || []).forEach(function (r) {
        const li = document.createElement("li");
        li.className = "r-" + (r.severity || "info");
        li.innerHTML = '<span class="dot"></span><span>' + escapeHtml(r.text) + "</span>";
        list.appendChild(li);
      });
    },

    renderDetails: function (box, details) {
      if (!box) return;
      box.innerHTML = "";
      Object.keys(details || {}).forEach(function (key) {
        let value = details[key];
        if (value === true) value = "Yes";
        else if (value === false) value = "No";
        if (value === null || value === undefined || value === "") return;
        const chip = document.createElement("span");
        chip.className = "detail-chip";
        chip.innerHTML =
          "<strong>" + escapeHtml(String(key).replace(/_/g, " ")) + ":</strong> " +
          escapeHtml(String(value).substring(0, 90));
        box.appendChild(chip);
      });
    },

    showResult: function (box, data) {
      box.classList.remove("result-hidden");
      box.scrollIntoView({ behavior: "smooth", block: "nearest" });
    },

    /* Prominent "BLACKLISTED / UNSAFE" warning box shown when a scan matches
       a threat record. Renders above the gauge and reasons. */
    renderBlacklistBanner: function (parent, blacklisted, reason) {
      if (!parent) return;
      const existing = parent.querySelector(".blacklist-banner");
      if (existing) existing.remove();
      if (!blacklisted) return;
      const banner = document.createElement("div");
      banner.className = "blacklist-banner";
      banner.innerHTML =
        '<div class="blacklist-banner-icon">&#128308;</div>' +
        '<div>' +
        '<div class="blacklist-banner-title">BLACKLISTED / UNSAFE</div>' +
        '<div class="blacklist-banner-text">' +
        "This address matches a known threat record in the TrustLens blacklist." +
        (reason ? " Reason: " + escapeHtml(reason) : "") +
        "</div></div>";
      parent.insertBefore(banner, parent.firstChild);
    }
  };

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = String(str == null ? "" : str);
    return div.innerHTML;
  }
  window.__escapeHtml = escapeHtml;

  /* ---- File drop zones -------------------------------------------------- */
  document.querySelectorAll(".drop-zone").forEach(function (zone) {
    const input = zone.querySelector('input[type="file"]');
    const label = zone.querySelector(".dz-filename");

    if (input) {
      zone.addEventListener("click", function () { input.click(); });
      zone.addEventListener("dragover", function (e) {
        e.preventDefault();
        zone.classList.add("dragover");
      });
      zone.addEventListener("dragleave", function () { zone.classList.remove("dragover"); });
      zone.addEventListener("drop", function (e) {
        e.preventDefault();
        zone.classList.remove("dragover");
        if (e.dataTransfer.files.length) {
          input.files = e.dataTransfer.files;
          if (label) label.textContent = e.dataTransfer.files[0].name;
        }
      });
      input.addEventListener("change", function () {
        if (label && input.files.length) label.textContent = input.files[0].name;
      });
    }
  });

  /* ---- Lightweight particle field -------------------------------------- */
  const canvas = document.getElementById("particles-js");
  if (canvas && canvas.getContext) {
    const ctx = canvas.getContext("2d");
    let w, h, particles = [];
    const COUNT = window.innerWidth < 768 ? 40 : 70;

    function resize() {
      w = canvas.width = canvas.offsetWidth;
      h = canvas.height = canvas.offsetHeight;
    }
    function spawn() {
      particles = [];
      for (let i = 0; i < COUNT; i++) {
        particles.push({
          x: Math.random() * w,
          y: Math.random() * h,
          r: Math.random() * 2 + 0.6,
          vx: (Math.random() - 0.5) * 0.35,
          vy: (Math.random() - 0.5) * 0.35,
          a: Math.random() * 0.35 + 0.08
        });
      }
    }
    function draw() {
      ctx.clearRect(0, 0, w, h);
      particles.forEach(function (p) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(124, 92, 255, " + p.a + ")";
        ctx.fill();
      });
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 110) {
            ctx.strokeStyle = "rgba(124, 92, 255, " + (0.12 * (1 - d / 110)) + ")";
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
          }
        }
      }
      requestAnimationFrame(draw);
    }
    resize();
    spawn();
    window.addEventListener("resize", function () { resize(); spawn(); });
    draw();
  }

  /* ---- Dashboard charts (lightweight canvas bars) ----------------------- */
  function drawBars(canvas, values, colors) {
    if (!canvas || !values.length) return;
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const W = canvas.offsetWidth, H = canvas.offsetHeight;
    canvas.width = W * dpr; canvas.height = H * dpr;
    ctx.scale(dpr, dpr);
    const max = Math.max.apply(null, values.concat([1]));
    const gap = 10, barW = (W - gap * (values.length - 1)) / values.length;
    values.forEach(function (v, i) {
      const bh = Math.max(4, (v / max) * (H - 14));
      const x = i * (barW + gap);
      const y = H - bh;
      const grad = ctx.createLinearGradient(0, y, 0, H);
      grad.addColorStop(0, colors[i] || "#7c5cff");
      grad.addColorStop(1, "rgba(124, 92, 255, 0.15)");
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.roundRect(x, y, barW, bh, [6, 6, 0, 0]);
      ctx.fill();
    });
  }
  window.TrustLens.drawBars = drawBars;
})();
