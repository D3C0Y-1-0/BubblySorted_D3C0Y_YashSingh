"use strict";

// Each tile asks its service for /health through the Guard. Only a failing service greys out.
async function checkTiles() {
  for (const tile of document.querySelectorAll(".tile")) {
    const service = tile.dataset.service;
    let ok = false;
    try {
      const r = await fetch(`/${service}/health`, { credentials: "same-origin", cache: "no-store" });
      ok = r.ok;
    } catch (_) {
      ok = false;
    }
    tile.classList.toggle("down", !ok);
    tile.querySelector(".state").textContent = ok ? "online" : "unavailable";
  }
}

function money(value) {
  return Number(value).toLocaleString(undefined, { style: "currency", currency: "EUR" });
}

async function showAccount() {
  const [balance, history] = await Promise.all([
    fetch("/transaction/balance", { credentials: "same-origin" }).then((r) => r.json()),
    fetch("/transaction/transactions", { credentials: "same-origin" }).then((r) => r.json()),
  ]);
  document.getElementById("balance").textContent = `${balance.account}: ${money(balance.balance)}`;
  const list = document.getElementById("history");
  list.replaceChildren(
    ...history.transactions.map((t) => {
      const li = document.createElement("li");
      li.textContent = `${t.date}  ${t.to || t.from}  ${money(t.amount)}`;
      return li;
    }),
  );
  document.getElementById("account-panel").classList.remove("hidden");
}

document.getElementById("login").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.target);
  const msg = document.getElementById("login-msg");
  msg.textContent = "Signing in…";
  try {
    const r = await fetch("/transaction/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: form.get("username"), password: form.get("password") }),
    });
    if (!r.ok) {
      msg.textContent = r.status === 401 ? "Wrong username or password." : `Sign-in failed (${r.status}).`;
      return;
    }
    msg.textContent = "Signed in.";
    await showAccount();
  } catch (_) {
    msg.textContent = "The bank is not reachable.";
  }
});

checkTiles();
setInterval(checkTiles, 10000);
