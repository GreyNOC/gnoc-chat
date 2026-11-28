chrome.runtime.onMessageExternal.addListener((msg, sender, reply) => reply({echo: msg, from: sender.origin}));
