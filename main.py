
import os
import sys
import names
import logging
import requests
import cfscrape
from threading import Thread

logging.basicConfig(
    level=logging.INFO,
    format=f"\x1b[38;5;197m[\x1b[0m%(asctime)s\x1b[38;5;197m]\x1b[0m -> \x1b[38;5;197m%(message)s\x1b[0m",
    datefmt="%H:%M:%S",
)

class Discord:
    """
    this is the main class which has all the apis and everything we need.
    """

    def __init__(self, token: str) -> None:
        self.token = token
        self.session = requests.session()
        self.cf_session = cfscrape.create_scraper()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.305 Chrome/69.0.3497.128 Electron/4.0.8 Safari/537.36",
            "Content-Type": "application/json",
            "Authorization": self.token
        }

    def _check_token(self) -> dict:
        r = self.session.get("https://discord.com/api/v9/users/@me", headers=self.headers)
        if r.status_code in (200, 201, 204):
           return {"error": False, "message": "token is valid"}
        else:
            return {"error": True, "message": "invalid discord token passed."}
    
    def _admin_report(self, guild: str, channel: str, message: str) -> dict:
        json = {
            "channel_id": channel,
            "guild_id": guild,
            "message_id": message,
            "reason": "1"
        }
        r = self.session.post("https://discord.com/api/v9/report", headers=self.headers, json=json)
        if r.status_code in (200, 201, 204):
            return {"error": False, "message": r.json()["id"]}
        else:
            return {"error": True, "message": "failed to report."}

    def _get_csrf(self) -> dict:
        r = self.session.get("https://support.discord.com/hc/api/internal/csrf_token.json")
        if "csrf_token" in r.text:
            return {"error": False, "message": r.json()["current_session"]["csrf_token"]}
        else:
            return {"error": True, "message": "failed to get csrf token for report forum."}
    
    def _forum_report(self, email: str, subject: str, description: str, channel: str, message_link: str, user: str) -> dict:
        csrf = self._get_csrf()
        description = "%s\n\nUser: %s\nChannel ID: %s\nMessage link: %s" % (description, user, channel, message_link)
        data = {
            "utf8": "✓",
            "request[ticket_form_id]": "360000029212",
            "request[anonymous_requester_email]": email,
            "request[custom_fields][360011846391]": "us_technical_issue",
            "request[subject]": subject,
            "request[description]": description,
            "request[description_mimetype]": "text/plain",
            "request[custom_fields][27322448]": "windows",
            "authenticity_token": csrf["message"]
        }
        headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.305 Chrome/69.0.3497.128 Electron/4.0.8 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "max-age=0",
            "content-type": "application/x-www-form-urlencoded",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-user": "?1",
            "sec-gpc": "1",
            "upgrade-insecure-requests": "1",
            "content-length": str(len(data))
        }
        r = self.cf_session.post("https://support.discord.com/hc/en-us/requests", data=data, headers=headers)
        if r.status_code in (200, 201, 204, 302):
            return {"error": False, "message": "sent report"}
        elif "RayID:" in r.text:
            ray = r.text.split("RayID: ")[1].split("\n")[0]
            return {"error": False, "message": "cloudflare ray id: %s" % (ray)}
        else:
            return {"error": True, "message": "failed to send report"}

class Threaded:
    """
    this is just to help you thread all the functions inside the class Discord.
    """

    def _admin_report(api, guild, channel, message):
        report = api._admin_report(guild, channel, message)
        if not report["error"]:
            logging.info("Sent report with id \x1b[0m->\x1b[38;5;197m %s" % (report["message"]))

    def _forum_report(api, email, subject, description, channel, message_link, user):
        report = api._forum_report(email, subject, description, channel, message_link, user)
        if not report["error"]:
            logging.info("Sent report")

    def _forum_report_aliasing(api, email, subject, description, channel, message_link, user):
        email = email.split("@")
        email = "%s+%s@%s" % (email[0], names.get_last_name(), email[1])
        report = api._forum_report(email, subject, description, channel, message_link, user)
        if not report["error"]:
            logging.info("Sent report")

if __name__ == "__main__":
    os.system("cls && title [Discord Mass Report Bot] - patched1337@github.com")

    module_index = 0
    for module in ["Admin Report", "Normal Report", "Email Aliasing"]:
        module_index += 1
        logging.info("[\x1b[0m%s\x1b[38;5;197m] %s" % (module_index, module))
    
    print()
    module = input("\x1b[38;5;197m[\x1b[0mMODULE\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
    if module == "1":
        print()
        token = input("\x1b[38;5;197m[\x1b[0mTOKEN\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")

        api = Discord(
            token=token
        )

        token_check = api._check_token()
        if token_check["error"]:
            logging.error(token_check["message"])
            sys.exit()

        guild = input("\x1b[38;5;197m[\x1b[0mGUILD\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        channel = input("\x1b[38;5;197m[\x1b[0mCHANNEL ID\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        message = input("\x1b[38;5;197m[\x1b[0mMESSAGE ID\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        print()

        while True:
            try:
                Thread(target=Threaded._admin_report, args=(api, guild, channel, message)).start()
            except Exception:
                pass

    elif module == "2":
        print()
        
        api = Discord(
            token="xxx"
        )
        
        email = input("\x1b[38;5;197m[\x1b[0mEMAIL\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        subject = input("\x1b[38;5;197m[\x1b[0mSUBJECT\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        description = input("\x1b[38;5;197m[\x1b[0mDESCRIPTION\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        channel = input("\x1b[38;5;197m[\x1b[0mCHANNEL ID\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        message = input("\x1b[38;5;197m[\x1b[0mMESSAGE LINK\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        user = input("\x1b[38;5;197m[\x1b[0mUSER ID\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        print()

        while True:
            try:
                Thread(target=Threaded._forum_report, args=(api, email, subject, description, channel, message, user)).start()
            except Exception:
                pass

    elif module == "3":
        print()
        
        api = Discord(
            token="xxx"
        )
        
        email = input("\x1b[38;5;197m[\x1b[0mEMAIL\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        subject = input("\x1b[38;5;197m[\x1b[0mSUBJECT\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        description = input("\x1b[38;5;197m[\x1b[0mDESCRIPTION\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        channel = input("\x1b[38;5;197m[\x1b[0mCHANNEL ID\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        message = input("\x1b[38;5;197m[\x1b[0mMESSAGE LINK\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        user = input("\x1b[38;5;197m[\x1b[0mUSER ID\x1b[38;5;197m] \x1b[0m->\x1b[38;5;197m ")
        print()

        while True:
            try:
                Thread(target=Threaded._forum_report_aliasing, args=(api, email, subject, description, channel, message, user)).start()
            except Exception:
                pass

    else:
        logging.error("Invalid module.")
