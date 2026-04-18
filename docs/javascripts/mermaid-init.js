window.addEventListener("load", function () {
  if (typeof mermaid === "undefined") {
    return;
  }

  mermaid.initialize({
    startOnLoad: true,
    theme: "neutral"
  });
});