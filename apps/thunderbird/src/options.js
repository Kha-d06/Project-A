import { localizePage, t } from "./lib/i18n.js";
import { cleanServerUrl } from "./lib/mail.js";

localizePage();
const form = document.getElementById("form");
const server = document.getElementById("server");
const auto = document.getElementById("auto");
const status = document.getElementById("status");

const stored = await messenger.storage.local.get({ serverUrl: "", autoCheck: true });
server.value = stored.serverUrl;
auto.checked = stored.autoCheck;

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const s = t();
  let origin;
  try {
    origin = cleanServerUrl(server.value);
  } catch (error) {
    status.textContent = error.message;
    return;
  }
  // Access to the one server the person chose, asked for at the moment they choose it.
  const granted = await messenger.permissions.request({ origins: [`${origin}/*`] });
  if (!granted) {
    status.textContent = s.denied;
    return;
  }
  await messenger.storage.local.set({ serverUrl: origin, autoCheck: auto.checked });
  server.value = origin;
  status.textContent = s.saved;
});
