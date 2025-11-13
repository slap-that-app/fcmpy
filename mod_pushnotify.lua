-- mod_pushnotify.lua
--
-- Simple Prosody module to send HTTP POST to an external push daemon
-- (such as fcmpy) when an XMPP user receives an offline message.
--
-- Configuration (in prosody.cfg.lua):
--
--   modules_enabled = {
--       -- ...
--       "pushnotify";
--   }
--
--   -- URL of the push daemon (fcmpy HTTP endpoint)
--   pushnotify_url = "http://127.0.0.1:9090/";
--
-- This module:
--   * hooks "message/offline/handle"
--   * for chat messages to offline users:
--       - extracts username from the JID
--       - sends HTTP POST with form body:
--           username=<user>&from=<from_jid>&type=message
--
-- The push daemon then uses its own templates / token store
-- to deliver an FCM push to the corresponding device(s).

local http = require "net.http";
local jid_split = require "util.jid".split;

local pushnotify_url;

local function get_pushnotify_url()
    if not pushnotify_url then
        pushnotify_url = module:get_option_string("pushnotify_url", "http://127.0.0.1:9090/");
    end
    return pushnotify_url;
end

-- Hook for offline messages
module:hook("message/offline/handle", function (event)
    local stanza = event.stanza;

    local to_jid = stanza.attr.to;
    local from_jid = stanza.attr.from;
    if not to_jid or not from_jid then
        return;
    end

    local username, host = jid_split(to_jid);
    if not username then
        return;
    end

    -- Only trigger for normal chat messages
    local msg_type = stanza.attr.type or "chat";
    if msg_type ~= "chat" then
        return;
    end

    module:log("info",
            "User %s is offline, triggering push for message from %s",
            username, from_jid
    );

    -- Build POST body (x-www-form-urlencoded)
    local body = string.format(
            "username=%s&from=%s&type=message",
            http.urlencode(username),
            http.urlencode(from_jid)
    );

    local url = get_pushnotify_url();

    -- Send HTTP request (non-blocking)
    http.request(
            url,
            { method = "POST", body = body },
            function (response_body, code, request)
                if code == 200 then
                    module:log("debug", "Push sent OK to daemon for %s (code=%s)", username, tostring(code));
                else
                    module:log("warn", "Push failed (code=%s) for %s", tostring(code), username);
                end
            end
    );

    -- Let the message continue to offline storage
    return;
end);

module:log("info", "mod_pushnotify loaded. Using pushnotify_url=%s", get_pushnotify_url());
