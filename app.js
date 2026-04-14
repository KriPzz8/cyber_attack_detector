const ATTACK_PATTERN_SOURCE =
  "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";

const fallbackKeywords = [
  "attack",
  "malware",
  "trojan",
  "unauthorized",
  "denial of service",
  "sql injection",
  "phishing",
  "root access",
  "threat"
];

let keywords = [];

const algorithms = {
  kmp: {
    name: "KMP",
    mode: "Smart and Efficient",
    timeComplexity: "O(n + m) per pattern",
    spaceComplexity: "O(m)"
  },
  "boyer-moore": {
    name: "Boyer-Moore",
    mode: "Faster Searching",
    timeComplexity: "Best: O(n / m), Worst: O(nm)",
    spaceComplexity: "O(k)"
  },
  "aho-corasick": {
    name: "Aho-Corasick",
    mode: "Multiple Detection",
    timeComplexity: "O(n + total pattern length)",
    spaceComplexity: "O(total pattern length)"
  }
};

const trafficInput = document.getElementById("trafficInput");
const detectBtn = document.getElementById("detectBtn");
const compareBtn = document.getElementById("compareBtn");
const sampleBtn = document.getElementById("sampleBtn");
const algorithmUsed = document.getElementById("algorithmUsed");
const keywordsFound = document.getElementById("keywordsFound");
const threatStatus = document.getElementById("threatStatus");
const threatMessage = document.getElementById("threatMessage");
const patternCount = document.getElementById("patternCount");
const keywordSource = document.getElementById("keywordSource");
const inputLength = document.getElementById("inputLength");
const bestSpeed = document.getElementById("bestSpeed");
const comparisonTable = document.getElementById("comparisonTable");
const timeChart = document.getElementById("timeChart");
const memoryChart = document.getElementById("memoryChart");
const accuracyChart = document.getElementById("accuracyChart");
const overallChart = document.getElementById("overallChart");

function preprocessText(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function setControlsLoading(isLoading) {
  detectBtn.disabled = isLoading;
  compareBtn.disabled = isLoading;
  sampleBtn.disabled = isLoading;
}

function setKeywordSource(label, sourceUrl) {
  if (!keywordSource) {
    return;
  }

  keywordSource.textContent = "";

  if (sourceUrl) {
    const link = document.createElement("a");
    link.href = sourceUrl;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = label;
    keywordSource.appendChild(link);
  } else {
    keywordSource.textContent = label;
  }
}

function normalizeKeyword(keyword) {
  return preprocessText(keyword);
}

function getMitreAttackKeywords(bundle) {
  const patterns = Array.isArray(bundle.objects) ? bundle.objects : [];
  const normalized = patterns
    .filter(
      (item) =>
        item.type === "attack-pattern" &&
        !item.revoked &&
        !item.x_mitre_deprecated &&
        typeof item.name === "string"
    )
    .map((item) => normalizeKeyword(item.name))
    .filter((item) => item.length > 2);

  return [...new Set(normalized)].sort((a, b) => a.localeCompare(b));
}

async function loadKeywords() {
  setControlsLoading(true);
  patternCount.textContent = "Loading...";
  setKeywordSource("Loading MITRE ATT&CK", ATTACK_PATTERN_SOURCE);

  try {
    const response = await fetch(ATTACK_PATTERN_SOURCE, { cache: "force-cache" });

    if (!response.ok) {
      throw new Error(`MITRE ATT&CK request failed: ${response.status}`);
    }

    const bundle = await response.json();
    const mitreKeywords = getMitreAttackKeywords(bundle);

    if (mitreKeywords.length === 0) {
      throw new Error("MITRE ATT&CK returned no attack patterns");
    }

    keywords = mitreKeywords;
    setKeywordSource("MITRE ATT&CK Enterprise", ATTACK_PATTERN_SOURCE);
  } catch (error) {
    console.warn(error);
    keywords = fallbackKeywords.map((keyword) => normalizeKeyword(keyword));
    setKeywordSource("Offline fallback keyword list");
  } finally {
    patternCount.textContent = String(keywords.length);
    setControlsLoading(false);
  }
}

function getSelectedAlgorithm() {
  const selected = document.querySelector('input[name="algorithmMode"]:checked');
  return selected ? selected.value : "kmp";
}

function buildLps(pattern) {
  const lps = new Array(pattern.length).fill(0);
  let len = 0;
  let i = 1;

  while (i < pattern.length) {
    if (pattern[i] === pattern[len]) {
      len += 1;
      lps[i] = len;
      i += 1;
    } else if (len > 0) {
      len = lps[len - 1];
    } else {
      lps[i] = 0;
      i += 1;
    }
  }

  return lps;
}

function kmpSearch(text, pattern) {
  const matches = [];
  if (!pattern || pattern.length > text.length) {
    return matches;
  }

  const lps = buildLps(pattern);
  let i = 0;
  let j = 0;

  while (i < text.length) {
    if (text[i] === pattern[j]) {
      i += 1;
      j += 1;

      if (j === pattern.length) {
        matches.push(i - j);
        j = lps[j - 1];
      }
    } else if (j > 0) {
      j = lps[j - 1];
    } else {
      i += 1;
    }
  }

  return matches;
}

function buildBadCharacterTable(pattern) {
  const table = {};

  for (let i = 0; i < pattern.length; i += 1) {
    table[pattern[i]] = i;
  }

  return table;
}

function boyerMooreSearch(text, pattern) {
  const matches = [];
  if (!pattern || pattern.length > text.length) {
    return matches;
  }

  const table = buildBadCharacterTable(pattern);
  let shift = 0;

  while (shift <= text.length - pattern.length) {
    let j = pattern.length - 1;

    while (j >= 0 && pattern[j] === text[shift + j]) {
      j -= 1;
    }

    if (j < 0) {
      matches.push(shift);
      const nextIndex = shift + pattern.length;
      shift += nextIndex < text.length ? pattern.length - (table[text[nextIndex]] ?? -1) : 1;
    } else {
      shift += Math.max(1, j - (table[text[shift + j]] ?? -1));
    }
  }

  return matches;
}

class AhoNode {
  constructor() {
    this.children = {};
    this.fail = null;
    this.outputs = [];
  }
}

class AhoCorasick {
  constructor(patterns) {
    this.root = new AhoNode();
    patterns.forEach((pattern) => this.insert(pattern));
    this.buildFailures();
  }

  insert(pattern) {
    let node = this.root;

    for (const char of pattern) {
      if (!node.children[char]) {
        node.children[char] = new AhoNode();
      }
      node = node.children[char];
    }

    node.outputs.push(pattern);
  }

  buildFailures() {
    const queue = [];

    Object.values(this.root.children).forEach((child) => {
      child.fail = this.root;
      queue.push(child);
    });

    while (queue.length > 0) {
      const current = queue.shift();

      Object.entries(current.children).forEach(([char, child]) => {
        queue.push(child);
        let failNode = current.fail;

        while (failNode && !failNode.children[char]) {
          failNode = failNode.fail;
        }

        child.fail = failNode ? failNode.children[char] : this.root;
        child.outputs = child.outputs.concat(child.fail.outputs);
      });
    }
  }

  search(text) {
    const results = {};
    let node = this.root;

    for (let i = 0; i < text.length; i += 1) {
      const char = text[i];

      while (node !== this.root && !node.children[char]) {
        node = node.fail;
      }

      if (node.children[char]) {
        node = node.children[char];
      } else {
        node = this.root;
      }

      node.outputs.forEach((pattern) => {
        if (!results[pattern]) {
          results[pattern] = [];
        }
        results[pattern].push(i - pattern.length + 1);
      });
    }

    return results;
  }
}

function runKmp(text) {
  const results = {};

  keywords.forEach((keyword) => {
    const positions = kmpSearch(text, keyword);
    if (positions.length > 0) {
      results[keyword] = positions;
    }
  });

  return results;
}

function runBoyerMoore(text) {
  const results = {};

  keywords.forEach((keyword) => {
    const positions = boyerMooreSearch(text, keyword);
    if (positions.length > 0) {
      results[keyword] = positions;
    }
  });

  return results;
}

function runAhoCorasick(text) {
  const machine = new AhoCorasick(keywords);
  return machine.search(text);
}

function runAlgorithm(text, algorithmKey) {
  if (algorithmKey === "kmp") {
    return runKmp(text);
  }

  if (algorithmKey === "boyer-moore") {
    return runBoyerMoore(text);
  }

  return runAhoCorasick(text);
}

function getFoundKeywords(results) {
  return Object.keys(results);
}

function getTotalHits(results) {
  return Object.values(results).reduce((total, positions) => total + positions.length, 0);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => {
    const entities = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;"
    };

    return entities[char];
  });
}

function estimateMemory(text, algorithmKey) {
  const totalPatternLength = keywords.join("").length;
  const longestPattern = Math.max(...keywords.map((keyword) => keyword.length));

  if (algorithmKey === "kmp") {
    return text.length + longestPattern;
  }

  if (algorithmKey === "boyer-moore") {
    return text.length + totalPatternLength + 128;
  }

  return text.length + totalPatternLength * 4;
}

function estimateOperationCount(text, algorithmKey) {
  const totalPatternLength = keywords.join("").length;

  if (algorithmKey === "kmp") {
    return text.length * keywords.length + totalPatternLength;
  }

  if (algorithmKey === "boyer-moore") {
    return Math.max(Math.round((text.length * keywords.length) / 2), 1);
  }

  return text.length + totalPatternLength;
}

function runComparison(text) {
  const keys = Object.keys(algorithms);
  const rawResults = keys.map((key) => {
    const start = performance.now();
    const results = runAlgorithm(text, key);
    const end = performance.now();

    return {
      key,
      name: algorithms[key].name,
      mode: algorithms[key].mode,
      results,
      foundKeywords: getFoundKeywords(results),
      totalHits: getTotalHits(results),
      time: Math.max(end - start, 0.001),
      memory: estimateMemory(text, key),
      operations: estimateOperationCount(text, key),
      timeComplexity: algorithms[key].timeComplexity,
      spaceComplexity: algorithms[key].spaceComplexity
    };
  });

  const union = new Set();
  rawResults.forEach((item) => item.foundKeywords.forEach((keyword) => union.add(keyword)));
  const expectedCount = Math.max(union.size, 1);
  const maxTime = Math.max(...rawResults.map((item) => item.time));
  const minTime = Math.min(...rawResults.map((item) => item.time));
  const maxMemory = Math.max(...rawResults.map((item) => item.memory));
  const minMemory = Math.min(...rawResults.map((item) => item.memory));

  return rawResults.map((item) => {
    const speedScore = maxTime === minTime ? 100 : ((maxTime - item.time) / (maxTime - minTime)) * 70 + 30;
    const memoryScore = maxMemory === minMemory ? 100 : ((maxMemory - item.memory) / (maxMemory - minMemory)) * 70 + 30;
    const accuracy = union.size === 0 ? 100 : (item.foundKeywords.length / expectedCount) * 100;
    const operationScore = 100 - Math.min((item.operations / Math.max(text.length * keywords.length, 1)) * 35, 35);
    const overall = speedScore * 0.35 + memoryScore * 0.25 + accuracy * 0.25 + operationScore * 0.15;

    return {
      ...item,
      speedScore,
      memoryScore,
      accuracy,
      operationScore,
      overall
    };
  });
}

function showResult(results, algorithmKey) {
  const foundKeywords = getFoundKeywords(results);
  algorithmUsed.textContent = algorithms[algorithmKey].name;

  if (foundKeywords.length > 0) {
    keywordsFound.textContent = foundKeywords.join(", ");
    threatStatus.textContent = "Threat Detected";
    threatStatus.className = "danger";
    threatMessage.textContent = `Possible attack found. Matched keyword(s): ${foundKeywords.join(", ")}.`;
  } else {
    keywordsFound.textContent = "No keywords found";
    threatStatus.textContent = "No Threat Detected";
    threatStatus.className = "safe";
    threatMessage.textContent = "The input string does not match any known attack keyword.";
  }
}

function renderSummary(text, comparison) {
  patternCount.textContent = String(keywords.length);
  inputLength.textContent = `${text.length} characters`;

  if (comparison.length === 0) {
    bestSpeed.textContent = "-";
    return;
  }

  const fastest = comparison.reduce((best, item) => (item.time < best.time ? item : best));
  bestSpeed.textContent = `${fastest.name} (${fastest.time.toFixed(3)} ms)`;
}

function renderComparisonTable(comparison) {
  comparisonTable.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Algorithm</th>
          <th>Mode</th>
          <th>Keywords Found</th>
          <th>Hits</th>
          <th>Speed</th>
          <th>Memory</th>
          <th>Accuracy</th>
          <th>Time Complexity</th>
          <th>Space Complexity</th>
        </tr>
      </thead>
      <tbody>
        ${comparison
          .map(
            (item) => `
              <tr>
                <td>${escapeHtml(item.name)}</td>
                <td>${escapeHtml(item.mode)}</td>
                <td>${escapeHtml(item.foundKeywords.join(", ") || "None")}</td>
                <td>${item.totalHits}</td>
                <td>${item.time.toFixed(3)} ms</td>
                <td>${item.memory} units</td>
                <td>${item.accuracy.toFixed(0)}%</td>
                <td>${escapeHtml(item.timeComplexity)}</td>
                <td>${escapeHtml(item.spaceComplexity)}</td>
              </tr>
            `
          )
          .join("")}
      </tbody>
    </table>
  `;
}

function drawBarGraph(canvas, title, labels, values, unit, lowerIsBetter) {
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  const padding = 48;
  const graphWidth = width - padding * 2;
  const graphHeight = height - padding * 2;
  const maxValue = Math.max(...values, 1);
  const colors = ["#4ea1ff", "#42d392", "#ffd166"];

  ctx.clearRect(0, 0, width, height);
  ctx.fillStyle = "#0d1420";
  ctx.fillRect(0, 0, width, height);

  ctx.strokeStyle = "#31435c";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padding, padding);
  ctx.lineTo(padding, height - padding);
  ctx.lineTo(width - padding, height - padding);
  ctx.stroke();

  ctx.fillStyle = "#eef4ff";
  ctx.font = "bold 15px Arial";
  ctx.fillText(title, padding, 25);

  ctx.fillStyle = "#9aa9bd";
  ctx.font = "12px Arial";
  ctx.fillText(lowerIsBetter ? "Lower is better" : "Higher is better", width - 145, 25);

  for (let i = 0; i <= 4; i += 1) {
    const y = height - padding - (graphHeight / 4) * i;
    const value = (maxValue / 4) * i;

    ctx.strokeStyle = "#1d2a3c";
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();

    ctx.fillStyle = "#9aa9bd";
    ctx.font = "11px Arial";
    ctx.fillText(value.toFixed(unit === "ms" ? 2 : 0), 8, y + 4);
  }

  const gap = 34;
  const barWidth = (graphWidth - gap * (values.length + 1)) / values.length;

  values.forEach((value, index) => {
    const barHeight = (value / maxValue) * graphHeight;
    const x = padding + gap + index * (barWidth + gap);
    const y = height - padding - barHeight;

    ctx.fillStyle = colors[index];
    ctx.fillRect(x, y, barWidth, barHeight);

    ctx.fillStyle = "#eef4ff";
    ctx.font = "bold 12px Arial";
    ctx.textAlign = "center";
    ctx.fillText(`${value.toFixed(unit === "ms" ? 3 : 0)} ${unit}`, x + barWidth / 2, y - 8);

    ctx.fillStyle = "#d8e4f5";
    ctx.font = "12px Arial";
    ctx.fillText(labels[index], x + barWidth / 2, height - padding + 22);
    ctx.textAlign = "left";
  });
}

function renderCharts(comparison) {
  const labels = comparison.map((item) => item.name);

  drawBarGraph(
    timeChart,
    "Execution Time",
    labels,
    comparison.map((item) => item.time),
    "ms",
    true
  );

  drawBarGraph(
    memoryChart,
    "Memory Usage",
    labels,
    comparison.map((item) => item.memory),
    "units",
    true
  );

  drawBarGraph(
    accuracyChart,
    "Accuracy",
    labels,
    comparison.map((item) => item.accuracy),
    "%",
    false
  );

  drawBarGraph(
    overallChart,
    "Overall Score",
    labels,
    comparison.map((item) => item.overall),
    "%",
    false
  );
}

function validateInput(text) {
  if (!text) {
    window.alert("Please enter a string first.");
    return false;
  }

  return true;
}

function analyzeSelectedAlgorithm() {
  const text = preprocessText(trafficInput.value);
  if (!validateInput(text)) {
    return;
  }

  const selected = getSelectedAlgorithm();
  const selectedResults = runAlgorithm(text, selected);
  const comparison = runComparison(text);

  showResult(selectedResults, selected);
  renderSummary(text, comparison);
  renderComparisonTable(comparison);
  renderCharts(comparison);
}

function compareAllAlgorithms() {
  const text = preprocessText(trafficInput.value);
  if (!validateInput(text)) {
    return;
  }

  const selected = getSelectedAlgorithm();
  const selectedResults = runAlgorithm(text, selected);
  const comparison = runComparison(text);

  showResult(selectedResults, selected);
  renderSummary(text, comparison);
  renderComparisonTable(comparison);
  renderCharts(comparison);
}

detectBtn.addEventListener("click", analyzeSelectedAlgorithm);
compareBtn.addEventListener("click", compareAllAlgorithms);

sampleBtn.addEventListener("click", () => {
  trafficInput.value =
    "Suspicious phishing attempt used valid accounts and command and scripting interpreter activity";
  analyzeSelectedAlgorithm();
});

loadKeywords();
