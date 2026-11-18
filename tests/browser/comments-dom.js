await (async () => {
  const check = (ok, msg) => { if (!ok) throw new Error(msg); };
  const id = document.querySelector("#incident-id").value.trim();
  const res = await fetch(`/api/incidents/${encodeURIComponent(id)}`);
  check(res.status === 200, `HTTP ${res.status}`);
  const data = await res.json();
  const marked = data.comments.filter(c => c.text.includes("data-lab05-marker"));
  check(marked.length > 0, "Fixture has no marker comment");
  check(document.querySelector("#lab05-marker-target")
    .getAttribute("data-lab05-marker") === null, "Reload before test");
  await load();
  const box = document.querySelector("#comments");
  check(box.querySelector("img") === null, "Comment became <img>");
  check(box.textContent.includes(marked[0].text), "Comment text changed");
  const first = box.childElementCount;
  await load();
  check(box.childElementCount === first, "Duplicated on re-render");
  await new Promise(r => setTimeout(r, 500));
  check(document.querySelector("#lab05-marker-target")
    .getAttribute("data-lab05-marker") === null, "Marker executed");
  console.log("PASS: comments rendered as text, re-render is stable");
})();
