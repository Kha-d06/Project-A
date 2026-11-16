"""Scam-language patterns for the message analyzer, in English and Arabic.

Each rule describes a manipulation technique, not a keyword blacklist: the
explanation shown to the user says what the technique is and why scammers use it.
"""

import re
from dataclasses import dataclass

from app.analyzers.types import Severity


@dataclass(frozen=True)
class MessageRule:
    category: str
    severity: Severity
    title: str
    explanation: str
    patterns: tuple[re.Pattern[str], ...]


def _compile(*expressions: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(expression, re.IGNORECASE) for expression in expressions)


RULES: tuple[MessageRule, ...] = (
    MessageRule(
        "credential_request",
        "high",
        "Asks for a verification code, PIN or password",
        "Banks, delivery firms and platforms never ask you to send them a one-time code or "
        "password. Anyone who has that code can take over the account it protects.",
        _compile(
            r"\b(send|share|give|tell|forward|reply with)\b.{0,40}\b(otp|verification code|"
            r"security code|one[- ]time (code|password)|pin( code)?|password|cvv)\b",
            r"\b(otp|verification code|security code|pin|cvv)\b.{0,30}\b(send|share|reply)\b",
            r"(أرسل|ارسل|زودنا|شارك|أدخل|ادخل).{0,40}(رمز التحقق|الرمز السري|كلمة المرور|"
            r"كلمة السر|الرقم السري|رمز التفعيل)",
        ),
    ),
    MessageRule(
        "account_threat",
        "medium",
        "Threatens that an account will be suspended or closed",
        "Warning that an account, card or service is about to be blocked is the most common "
        "way to rush someone into clicking a link without checking it.",
        _compile(
            r"\b(account|card|access|service|subscription|mailbox)\b.{0,50}\b(suspend(ed)?|"
            r"lock(ed)?|block(ed)?|restrict(ed)?|deactivat(ed|ion)|clos(ed|ure)|disabled|frozen)\b",
            r"\b(unusual|suspicious|unauthori[sz]ed)\b.{0,20}\b(activity|login|sign[- ]in|"
            r"transaction)\b",
            r"(تم|سيتم|سوف يتم).{0,20}(إيقاف|ايقاف|تعليق|حظر|تجميد|إغلاق|اغلاق).{0,30}"
            r"(حسابك|بطاقتك|خدمتك|حسابكم|بطاقتكم)",
            r"(حسابك|بطاقتك).{0,30}(موقوف|معلق|محظور|مجمد)",
        ),
    ),
    MessageRule(
        "delivery_scam",
        "medium",
        "Delivery problem that needs a payment or a link",
        "Fake courier messages claim a parcel is held until you pay a small fee or confirm "
        "your address. The fee page collects your card details.",
        _compile(
            r"\b(parcel|package|shipment|delivery|courier)\b.{0,80}\b(fee|pay(ment)?|customs|"
            r"reschedul\w+|confirm your address|could not be delivered|on hold|held|pending)\b",
            r"(شحنتك|طردك|الشحنة|الطرد).{0,80}(رسوم|دفع|سداد|تحديث العنوان|تأكيد العنوان|"
            r"الجمارك|معلقة|متوقفة|تعذر)",
        ),
    ),
    MessageRule(
        "prize_scam",
        "medium",
        "Says you won a prize, lottery or giveaway",
        "Unexpected winnings are bait. The next step is always a “processing fee” or a "
        "request for personal and banking details.",
        _compile(
            r"\b(you('ve| have)? (won|been selected|been chosen)|congratulations)\b.{0,80}"
            r"\b(prize|lottery|reward|gift|giveaway|winner|iphone|voucher|\$|usd|cash)\b",
            r"\bclaim (your|the) (prize|reward|gift|winnings)\b",
            r"(مبروك|تهانينا|ألف مبروك).{0,60}(ربحت|فزت|جائزة|الفائز)",
            r"(ربحت|فزت).{0,40}(جائزة|مبلغ|سيارة|آيفون|ايفون)",
        ),
    ),
    MessageRule(
        "job_scam",
        "medium",
        "Job offer with unrealistic pay or no real hiring process",
        "Offers of high pay for simple remote tasks, with no interview, usually lead to a "
        "request for an upfront payment or to moving money for criminals.",
        _compile(
            r"\b(earn|make|salary|paid)\b.{0,40}(\$|usd|aed|sar|egp|£|€)\s?\d[\d,]*.{0,30}"
            r"\b(per|a|each|/)\s?(day|hour|week)\b",
            r"\b(work from home|part[- ]time|remote)\b.{0,60}\b(no experience|easy|simple tasks|"
            r"daily pay|paid daily)\b",
            r"\b(hr|recruit(er|ment)|hiring)\b.{0,80}\b(whatsapp|telegram)\b",
            r"(وظيفة|فرصة عمل|عمل من المنزل|دوام جزئي).{0,80}(بدون خبرة|يوميا|يومياً|راتب يومي|"
            r"دخل يومي|واتساب|تيليجرام)",
        ),
    ),
    MessageRule(
        "investment_scam",
        "medium",
        "Promises guaranteed or unusually high investment returns",
        "No real investment guarantees a profit. Guaranteed returns, “risk-free” trading and "
        "pressure to act quickly are hallmarks of investment fraud.",
        _compile(
            r"\b(guaranteed|risk[- ]free|double your)\b.{0,40}\b(return|profit|income|money|"
            r"investment|crypto|bitcoin)\b",
            r"\b\d{2,4}\s?%\s?(daily|weekly|monthly)?\s?(return|profit|roi)\b",
            r"(أرباح|ارباح|عائد|ربح).{0,30}(مضمونة|مضمون|يومية|يومي|بدون مخاطر)",
            r"(استثمر|استثمار).{0,60}(مضمون|ضاعف|مضاعفة)",
        ),
    ),
    MessageRule(
        "payment_pressure",
        "medium",
        "Asks for payment by gift card, crypto or money transfer",
        "Gift cards, cryptocurrency and wire transfers cannot be reversed, which is exactly "
        "why scammers ask for them. Legitimate organisations do not.",
        _compile(
            r"\b(gift ?cards?|itunes cards?|google play cards?|steam cards?)\b",
            r"\b(pay|send|transfer|deposit)\b.{0,50}\b(bitcoin|btc|usdt|crypto|western union|"
            r"moneygram|wire transfer)\b",
            r"(بطاقات? (هدايا|آيتونز|ايتونز|جوجل بلاي)|ويسترن يونيون|حوالة فورية)",
            r"(حول|حوّل|ارسل|أرسل|ادفع).{0,40}(بيتكوين|عملات رقمية|USDT)",
        ),
    ),
    MessageRule(
        "personal_data_request",
        "medium",
        "Asks for identity or banking details",
        "Requests to “confirm” or “update” card numbers, ID numbers or bank details by "
        "message or through a link are a standard phishing step.",
        _compile(
            r"\b(confirm|verify|update|provide|submit)\b.{0,40}\b(card (number|details)|"
            r"bank(ing)? (details|information)|account (number|details)|national id|passport|"
            r"social security|personal (details|information)|billing (details|information))\b",
            r"(تحديث|تأكيد|تاكيد|إدخال|ادخال).{0,40}(بياناتك|بيانات البطاقة|رقم البطاقة|"
            r"رقم الهوية|معلوماتك البنكية|بياناتكم)",
        ),
    ),
    MessageRule(
        "urgency",
        "low",
        "Creates time pressure",
        "Deadlines and “act now” wording are meant to stop you from pausing to check. On "
        "its own this is weak evidence, since plenty of genuine messages are urgent.",
        _compile(
            r"\b(urgent(ly)?|immediately|act now|right away|final (notice|warning)|"
            r"within \d+ ?(hours?|hrs?|minutes?|mins?)|expires? (today|soon)|last chance)\b",
            r"(عاجل|فورا|فوراً|حالا|حالاً|خلال \d+ (ساعة|ساعات|دقيقة|دقائق)|آخر (فرصة|تنبيه|إشعار))",
        ),
    ),
    MessageRule(
        "off_platform",
        "low",
        "Moves the conversation to a private chat app",
        "Being asked to continue on WhatsApp or Telegram takes you away from any platform "
        "that could moderate or trace the conversation.",
        _compile(
            r"\b(contact|message|add|reach|text)\b.{0,30}\b(on|via|through)?\s?"
            r"(whatsapp|telegram|signal)\b",
            r"(تواصل|راسلنا|راسلني|كلمني).{0,30}(واتساب|واتس اب|تيليجرام|تلجرام)",
        ),
    ),
)

URL_PATTERN = re.compile(
    r"""(?:https?://|www\.)[^\s<>"'،؛]+"""
    r"""|\b(?:[a-z0-9-]+\.)+(?:com|net|org|info|xyz|top|site|online|shop|live|link|click|"""
    r"""app|co|io|me|ly|gl|cc|ru|cn|tk|ae|sa|eg|uk)\b(?:/[^\s<>"'،؛]*)?""",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)
PHONE_PATTERN = re.compile(r"(?<![\w.])\+?\d[\d\s().-]{7,16}\d(?!\w)")
