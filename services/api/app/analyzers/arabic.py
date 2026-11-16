"""Arabic wording for technical findings and check names.

Analyzers write findings in English. For scans submitted in Arabic, each finding
is matched against this catalogue by its English title and rewritten in Arabic;
dynamic parts (domains, counts, names) are carried over from the English title.
Evidence is never translated: it is what was actually observed. Anything not in
the catalogue stays in English, and the report says so.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass

from app.analyzers.types import Check, FindingData


@dataclass(frozen=True)
class Entry:
    pattern: re.Pattern[str]
    title: Callable[[re.Match[str]], str]
    explanation: str


def _e(pattern: str, title: str | Callable[[re.Match[str]], str], explanation: str) -> Entry:
    render = title if callable(title) else (lambda _match, text=title: text)
    return Entry(re.compile(pattern + r"$"), render, explanation)


def _days(value: str) -> str:
    """Arabic number agreement: one, two, three to ten, eleven and above."""
    n = int(value)
    if n == 0:
        return "اليوم"
    if n == 1:
        return "قبل يوم واحد"
    if n == 2:
        return "قبل يومين"
    if 3 <= n <= 10:
        return f"قبل {n} أيام"
    return f"قبل {n} يومًا"


_DANGER_ADVICE = "لا تفتحه ولا تُدخل فيه أي بيانات."

CATALOGUE: tuple[Entry, ...] = (
    # --- Threat intelligence --------------------------------------------------------
    _e(
        r"This exact link is listed by (?P<src>.+)",
        lambda m: f"هذا الرابط مدرج بالضبط لدى {m['src']}",
        "أُبلغ عن هذا العنوان وفُهرس على أنه يوزّع برمجيات ضارة. " + _DANGER_ADVICE,
    ),
    _e(
        r"This link is listed by URLhaus",
        "هذا الرابط مدرج لدى URLhaus",
        "يتتبع URLhaus العناوين المستخدمة لتوزيع البرمجيات الضارة. " + _DANGER_ADVICE,
    ),
    _e(
        r"Google lists this link as dangerous",
        "تُدرج Google هذا الرابط على أنه خطير",
        "تُدرج خدمة Google Web Risk هذا العنوان ضمن المواقع الخطيرة، وتعرض المتصفحات صفحة تحذير حمراء له.",
    ),
    _e(
        r"Other links on this host are listed by (?P<src>.+)",
        lambda m: f"روابط أخرى على هذا الخادم مدرجة لدى {m['src']}",
        "أُبلغ عن عنوان آخر على الخادم نفسه. في الاستضافات المشتركة وخدمات مشاركة الملفات لا يعني ذلك الكثير عن رابطك، فاعتبره سياقًا لا دليلًا.",
    ),
    _e(
        r"(?P<subject>.+) was reported by SENTINEL users as a scam",
        "أبلغ مستخدمو SENTINEL عن هذا على أنه احتيال",
        "أبلغ أشخاص عنه وراجع أحد المشرفين البلاغات وأكّدها. تعامل معه على أنه احتيال محتمل.",
    ),
    _e(
        r"This file is listed as malware by (?P<src>.+)",
        lambda m: f"هذا الملف مدرج كبرمجية ضارة لدى {m['src']}",
        "تطابق بصمة الملف عينة فُهرست على أنها برمجية ضارة. احذفه ولا تفتحه.",
    ),
    _e(
        r"A file inside this archive is listed as malware by (?P<src>.+)",
        lambda m: f"ملف داخل هذا الأرشيف مدرج كبرمجية ضارة لدى {m['src']}",
        "أحد ملفات الأرشيف يطابق عينة ضارة مفهرسة. احذف الأرشيف ولا تفتح أي شيء بداخله.",
    ),
    _e(
        r"App contains an address listed by (?P<src>.+)",
        lambda m: f"يحتوي التطبيق على عنوان مدرج لدى {m['src']}",
        "يتصل التطبيق بعنوان معروف بتوزيع برمجيات ضارة أو التحكم بها. لا تثبّته.",
    ),
    # --- Signatures -----------------------------------------------------------------
    _e(
        r"EICAR antivirus test file.*",
        "ملف اختبار مضاد الفيروسات EICAR",
        "هذا نمط الاختبار القياسي للتأكد من عمل برامج الحماية. وهو غير ضار، ويُبلَّغ عنه كما تُبلَّغ البرمجيات الضارة الحقيقية.",
    ),
    _e(
        r"ClamAV identified this file as (?P<sig>.+)",
        lambda m: f"تعرّف ClamAV على هذا الملف بأنه {m['sig']}",
        "يطابق الملف توقيعًا في قاعدة بيانات ClamAV للبرمجيات الضارة. احذفه ولا تفتحه.",
    ),
    _e(
        r"(?P<n>\d+) of (?P<total>\d+) antivirus engines flag this file",
        lambda m: f"{m['n']} من أصل {m['total']} من محركات مكافحة الفيروسات تصنّف هذا الملف ضارًا",
        "فحص VirusTotal هذا الملف نفسه من قبل، ووصفته محركات مستقلة بأنه ضار. احذفه إذا كان العدد كبيرًا، وتعامل معه بحذر في كل الأحوال.",
    ),
    # --- Links ----------------------------------------------------------------------
    _e(
        r"Domain mixes letters from different alphabets",
        "يخلط النطاق حروفًا من أبجديات مختلفة",
        "تبدو بعض الحروف من أبجديات أخرى مطابقة للحروف اللاتينية، ويستخدمها المحتالون لتقليد مواقع معروفة.",
    ),
    _e(
        r"Domain uses look-alike characters to imitate “(?P<brand>.+)”",
        lambda m: f"يستخدم النطاق حروفًا متشابهة لتقليد «{m['brand']}»",
        "يبدو العنوان كأنه الموقع الحقيقي لكنه مكتوب بحروف مختلفة. " + _DANGER_ADVICE,
    ),
    _e(
        r"Domain is a look-alike of “(?P<brand>.+)”",
        lambda m: f"النطاق تقليد لـ«{m['brand']}»",
        "يختلف العنوان عن العلامة الحقيقية بحرف أو حرفين فقط، وهو أسلوب شائع في مواقع التصيد.",
    ),
    _e(
        r"“(?P<brand>.+)” appears in the address, but the site is not (?P<owner>.+)'s",
        lambda m: f"يظهر «{m['brand']}» في العنوان، لكن الموقع ليس تابعًا لها",
        "وضع اسم علامة معروفة داخل عنوان موقع آخر حيلة شائعة لإقناعك بأنك في الموقع الحقيقي.",
    ),
    _e(
        r"Link points to a numeric IP address instead of a domain name",
        "يشير الرابط إلى عنوان IP رقمي بدل اسم نطاق",
        "المواقع الحقيقية تستخدم أسماء نطاقات. الروابط إلى أرقام مباشرة شائعة في البرمجيات الضارة والتصيد.",
    ),
    _e(
        r"Link hides its real destination behind an “@” sign",
        "يخفي الرابط وجهته الحقيقية خلف علامة «@»",
        "كل ما يسبق علامة @ في الرابط يُتجاهَل، والوجهة الحقيقية هي ما بعدها.",
    ),
    _e(
        r"Link uses a URL shortener",
        "يستخدم الرابط خدمة اختصار روابط",
        "الروابط المختصرة تخفي وجهتها. هذا ليس ضارًا بحد ذاته، لكن تحقق من الوجهة قبل فتحها.",
    ),
    _e(
        r"Link uses an unusual port \((?P<port>\d+)\)",
        lambda m: f"يستخدم الرابط منفذًا غير معتاد ({m['port']})",
        "تستخدم المواقع العادية المنافذ القياسية. المنافذ غير المعتادة شائعة في الخوادم المؤقتة والضارة.",
    ),
    _e(
        r"Unusually long or deeply nested address",
        "عنوان طويل أو متداخل بشكل غير معتاد",
        "تُستخدم العناوين الطويلة جدًا أحيانًا لإخفاء الجزء المهم من الرابط.",
    ),
    _e(
        r"Link downloads a program or script",
        "يقوم الرابط بتنزيل برنامج أو نص برمجي",
        "يؤدي هذا الرابط مباشرة إلى ملف قابل للتشغيل. لا تشغّله إلا إذا كنت تثق بمصدره تمامًا.",
    ),
    _e(
        r"Sign-in or account page without an encrypted connection",
        "صفحة تسجيل دخول أو حساب بدون اتصال مشفّر",
        "أي شيء تكتبه في هذه الصفحة يمكن قراءته أثناء انتقاله. لا تُدخل كلمة مرور فيها.",
    ),
    _e(
        r"Domain was registered (?P<n>\d+) days ago",
        lambda m: f"سُجّل النطاق {_days(m['n'])}",
        "تستخدم معظم مواقع التصيد نطاقات سُجّلت قبل الهجوم بأيام أو أسابيع. النطاق الجديد ليس ضارًا تلقائيًا، لكنه يستحق حذرًا إضافيًا.",
    ),
    _e(
        r"The site's first security certificate was issued (?P<n>\d+) days ago",
        lambda m: f"صدرت أول شهادة أمان للموقع {_days(m['n'])}",
        "تُظهر سجلات الشهادات العامة أن هذا النطاق بدأ استخدام HTTPS مؤخرًا جدًا، وتُجهَّز مواقع التصيد عادةً قبل استخدامها بأيام.",
    ),
    _e(
        r"Link leads to a private or internal network address",
        "يؤدي الرابط إلى عنوان شبكة خاصة أو داخلية",
        "المواقع العامة لا تكون على عناوين خاصة. قد يستهدف رابط كهذا أجهزة شبكتك، مثل صفحة إدارة الراوتر.",
    ),
    _e(
        r"Link redirects to a different site \((?P<site>.+)\)",
        lambda m: f"يحوّل الرابط إلى موقع آخر ({m['site']})",
        "العنوان الذي أرسلته يحوّل إلى نطاق آخر، وطُبقت الفحوصات على تلك الوجهة أيضًا.",
    ),
    _e(
        r"The site's security certificate is not valid",
        "شهادة أمان الموقع غير صالحة",
        "الشهادة منتهية أو صادرة لموقع آخر أو من جهة غير موثوقة، وستعرض المتصفحات تحذيرًا قبل فتح الصفحة.",
    ),
    _e(
        r"The page is served without encryption",
        "تُعرض الصفحة بدون تشفير",
        "تستخدم الوجهة http://، لذا يمكن قراءة أي شيء ترسله إليها أو تغييره. لا تُدخل كلمات مرور أو بيانات دفع.",
    ),
    # --- Websites -------------------------------------------------------------------
    _e(
        r"Sign-in or payment page presents itself as (?P<brand>.+)",
        lambda m: f"صفحة دخول أو دفع تقدّم نفسها على أنها {m['brand']}",
        "تطلب الصفحة كلمة مرور أو بيانات بطاقة وتستخدم اسم علامة معروفة أو صورها، لكنها مستضافة على نطاق لا يخصها. هذا هو الشكل المعتاد لصفحات التصيد.",
    ),
    _e(
        r"Asks for sensitive details on a free hosting service",
        "تطلب بيانات حساسة على خدمة استضافة مجانية",
        "يمكن لأي شخص نشر صفحة على هذه الخدمات. البنوك والخدمات الكبرى لا تستضيف صفحات الدخول عليها.",
    ),
    _e(
        r"Password or card form sends data without encryption",
        "نموذج كلمة المرور أو البطاقة يرسل البيانات بدون تشفير",
        "يُرسل النموذج إلى عنوان http://، لذا يمكن للآخرين على الشبكة قراءة ما يُكتب فيه.",
    ),
    _e(
        r"Asks for a password or card details over an unencrypted connection",
        "تطلب كلمة مرور أو بيانات بطاقة عبر اتصال غير مشفّر",
        "الصفحة نفسها تُعرض عبر http://، لذا يمكن اعتراض أي شيء يُدخل فيها.",
    ),
    _e(
        r"Sign-in form sends your details to a different site",
        "نموذج الدخول يرسل بياناتك إلى موقع آخر",
        "يُرسل النموذج إلى نطاق مختلف. نماذج الدخول الحقيقية ترسل دائمًا تقريبًا إلى الجهة نفسها.",
    ),
    _e(
        r"Page script (?P<what>.+)",
        "نص برمجي في الصفحة يتصرف بشكل مريب",
        "النصوص البرمجية المموّهة شائعة في أدوات التصيد والصفحات الضارة، وإن كانت بعض المواقع المشروعة تستخدم أساليب مشابهة.",
    ),
    _e(
        r"Page loads content in an invisible frame",
        "تحمّل الصفحة محتوى في إطار غير مرئي",
        "تُستخدم الإطارات المخفية أحيانًا لتحميل محتوى تتبع أو محتوى ضار دون أن يلاحظ الزائر.",
    ),
    _e(
        r"Page immediately forwards visitors elsewhere",
        "تحوّل الصفحة الزوار فورًا إلى مكان آخر",
        "تستخدم الصفحة تعليمة تحديث لإرسال المتصفح إلى عنوان آخر، ولم يتبعها SENTINEL.",
    ),
    _e(
        r"Anyone can send email that claims to come from this domain",
        "يمكن لأي شخص إرسال بريد يدّعي أنه من هذا النطاق",
        "لا ينشر النطاق سجلات SPF أو DMARC، فلا تستطيع خدمات البريد التمييز بين الرسائل المزورة والحقيقية. احذر من الرسائل التي تدّعي أنها منه.",
    ),
    # --- Files ----------------------------------------------------------------------
    _e(
        r"Document contains macros.*",
        "يحتوي المستند على وحدات ماكرو",
        "وحدات الماكرو برامج صغيرة داخل المستند، وهي الطريقة الأكثر شيوعًا لنشر البرمجيات الضارة عبر ملفات Office. لا تضغط «تمكين المحتوى» إلا إذا كنت تثق بالمرسل.",
    ),
    _e(
        r"Macro runs automatically and uses risky functions",
        "يعمل الماكرو تلقائيًا ويستخدم وظائف خطرة",
        "يبدأ الماكرو بمجرد فتح المستند ويستطيع تنزيل ملفات أو تشغيل أوامر. هذا نمط شائع في البرمجيات الضارة.",
    ),
    _e(
        r"Contains old-style Excel 4 macros",
        "يحتوي على وحدات ماكرو قديمة من نوع Excel 4",
        "نادرًا ما تُستخدم هذه الوحدات القديمة اليوم إلا لتجاوز أدوات الحماية.",
    ),
    _e(
        r"Macro code contains web addresses or other network indicators",
        "يحتوي كود الماكرو على عناوين ويب أو مؤشرات شبكة",
        "يتصل الماكرو بالإنترنت، وهو ما تفعله البرمجيات الضارة لتنزيل الجزء التالي منها.",
    ),
    _e(
        r"Document contains macros that could not be fully analysed",
        "يحتوي المستند على وحدات ماكرو تعذّر تحليلها بالكامل",
        "قد يكون الماكرو مموّهًا عمدًا. تعامل مع المستند بحذر.",
    ),
    _e(
        r"File name is made to look like a document but is a program",
        "اسم الملف يجعله يبدو مستندًا لكنه برنامج",
        "إخفاء برنامج خلف اسم مستند خدعة كلاسيكية لدفعك إلى تشغيله.",
    ),
    _e(
        r"The file name disguises a program as a document",
        "اسم الملف يُخفي برنامجًا على أنه مستند",
        "إخفاء برنامج خلف اسم مستند خدعة كلاسيكية لدفعك إلى تشغيله.",
    ),
    _e(
        r"“(?P<name>.+)” is a (?P<kind>.+) disguised as a \.(?P<ext>\w+) file",
        lambda m: f"«{m['name']}» برنامج متنكر في هيئة ملف .{m['ext']}",
        "يحتوي الأرشيف على برنامج اسمه يوحي بأنه مستند أو صورة، وهي خدعة كلاسيكية لدفعك إلى تشغيله.",
    ),
    _e(
        r"File is really a (?P<kind>.+), not what its name suggests",
        "نوع الملف الحقيقي يختلف عما يوحي به اسمه",
        "محتوى الملف لا يطابق امتداده. قد يكون ذلك خطأ بريئًا، لكنه أيضًا أسلوب لإخفاء ملفات ضارة.",
    ),
    _e(
        r"Archive expands to an extreme size",
        "يتمدد الأرشيف إلى حجم هائل",
        "المحتوى مضغوط بدرجة لا تحققها الملفات العادية. صُممت أرشيفات كهذه لاستنزاف المساحة أو تعطيل البرامج التي تفتحها.",
    ),
    _e(
        r"Archive tries to write files outside its own folder",
        "يحاول الأرشيف كتابة ملفات خارج مجلده",
        "بعض المدخلات تستخدم مسارات تخرج من مجلد الاستخراج، وقد تستبدل ملفات أخرى على الجهاز عند فكّها ببرامج ضعيفة.",
    ),
    _e(
        r"Archive contains programs or scripts",
        "يحتوي الأرشيف على برامج أو نصوص برمجية",
        "إرسال برنامج داخل أرشيف طريقة شائعة لتجاوز مرشحات البريد. لا تشغّلها إلا إذا كنت تعرف ما هي بالضبط.",
    ),
    _e(
        r"Archive is password-protected",
        "الأرشيف محمي بكلمة مرور",
        "لا يستطيع أي ماسح فحص المحتوى المشفّر. إرسال مرفق محمي بكلمة مرور مع كلمة المرور في الرسالة نفسها أسلوب معروف لنشر البرمجيات الضارة.",
    ),
    _e(
        r"PDF can launch another program",
        "يمكن لملف PDF تشغيل برنامج آخر",
        "يحتوي المستند على إجراء تشغيل يطلب من القارئ بدء برنامج أو ملف خارجي، ولا سبب لذلك في المستندات العادية.",
    ),
    _e(
        r"PDF contains JavaScript.*",
        "يحتوي ملف PDF على JavaScript",
        "تستخدم النماذج التفاعلية نصوصًا برمجية، لكن تستخدمها أيضًا ثغرات تستهدف قارئات PDF القديمة. افتحه فقط في قارئ محدَّث.",
    ),
    _e(
        r"PDF carries an embedded file",
        "يحمل ملف PDF ملفًا مضمَّنًا",
        "هناك ملف آخر مرفق داخل المستند. احذر من فتح المرفقات من داخل المستندات.",
    ),
    _e(
        r"This is a (?P<kind>.+)",
        "هذا برنامج قابل للتشغيل",
        "تستطيع البرامج فعل أي شيء يسمح به حسابك. لا يمكن للفحص الثابت معرفة ما يفعله البرنامج عند تشغيله، فشغّله فقط إذا كنت تثق بمصدره.",
    ),
    _e(
        r"This download is a program or script",
        "هذا التنزيل برنامج أو نص برمجي",
        "شغّل البرامج فقط إذا كنت تثق تمامًا بالموقع الذي نزّلتها منه.",
    ),
    _e(
        r"Parts of the program are compressed or encrypted",
        "أجزاء من البرنامج مضغوطة أو مشفّرة",
        "تضغط البرمجيات الضارة نفسها غالبًا لإخفاء محتواها عن الماسحات، وإن كانت بعض البرامج المشروعة تفعل ذلك أيضًا.",
    ),
    _e(
        r"Program hides which system functions it uses",
        "يُخفي البرنامج وظائف النظام التي يستخدمها",
        "البرامج العادية تعلن عن الوظائف التي تحتاجها. إخفاؤها أسلوب شائع في البرمجيات الضارة.",
    ),
    # --- QR, apps, AI ----------------------------------------------------------------
    _e(
        r"QR code starts a payment to (?P<payee>.+)",
        lambda m: f"يبدأ رمز QR دفعة إلى {m['payee']}",
        "تأكد من اسم المستفيد والمبلغ قبل التأكيد. ملصقات QR المزيفة فوق الرموز الحقيقية أسلوب احتيال شائع.",
    ),
    _e(
        r"QR code asks for a (?P<net>.+) payment",
        lambda m: f"يطلب رمز QR دفعة عبر {m['net']}",
        "مدفوعات العملات الرقمية لا يمكن استردادها. تحقق من المستفيد بطريقة أخرى قبل الدفع.",
    ),
    _e(
        r"QR code joins an open Wi-Fi network",
        "ينضم رمز QR إلى شبكة Wi-Fi مفتوحة",
        "يمكن لأي شخص على شبكة مفتوحة رؤية حركة البيانات غير المشفّرة. لا تستخدمها للخدمات المصرفية.",
    ),
    _e(
        r"QR code opens (?P<host>.+)",
        lambda m: f"يفتح رمز QR الموقع {m['host']}",
        "هذه وجهة الرمز. الفحوصات أدناه تقيّم ذلك الرابط.",
    ),
    _e(
        r"Signed with a developer test certificate",
        "موقّع بشهادة اختبار للمطورين",
        "التطبيقات المنشورة رسميًا لا تُوقَّع بشهادات الاختبار. هذا التطبيق على الأرجح لم يأتِ من متجر رسمي.",
    ),
    _e(
        r"App is named like (?P<brand>.+) but is not the official app",
        lambda m: f"يحمل التطبيق اسمًا يشبه {m['brand']} لكنه ليس التطبيق الرسمي",
        "اسم الحزمة أو التوقيع لا يطابق التطبيق الرسمي. نزّل التطبيقات من المتجر الرسمي فقط.",
    ),
    _e(
        r"MobSF reported (?P<n>\d+) high-severity issue\(s\)",
        lambda m: f"أبلغ MobSF عن {m['n']} مشكلة عالية الخطورة",
        "وجد التحليل المتعمق مشكلات أمنية جدية في التطبيق.",
    ),
    _e(
        r"An AI model thinks this reads like a scam",
        "يرى نموذج ذكاء اصطناعي أن هذا يشبه رسائل الاحتيال",
        "هذا رأي آلي ولا يغيّر الحكم وحده.",
    ),
)

CHECK_LABELS_AR = {
    "url_patterns": "أنماط العنوان",
    "local_threat_feed": "الروابط الضارة المعروفة",
    "urlhaus_api": "فحص السمعة المباشر",
    "web_risk": "Google Web Risk",
    "redirects": "الوجهة وإعادة التوجيه",
    "tls": "شهادة الأمان",
    "domain_age": "تاريخ تسجيل النطاق",
    "certificates": "سجل الشهادات",
    "page": "محتوى الصفحة",
    "rendered_page": "الصفحة كما يعرضها المتصفح",
    "dns": "سجلات DNS",
    "mail_policy": "حماية البريد (SPF وDMARC)",
    "message_patterns": "لغة الاحتيال والتصيد",
    "embedded_links": "الروابط في الرسالة",
    "ai_classification": "رأي ثانٍ من الذكاء الاصطناعي",
    "file_identity": "نوع الملف وبصمته",
    "static_inspection": "البنية والمحتوى المضمَّن",
    "yara": "قواعد التوقيعات",
    "hash_reputation": "بصمات البرمجيات الضارة المعروفة",
    "antivirus": "توقيعات مضاد الفيروسات",
    "virustotal": "البحث عن البصمة في VirusTotal",
    "qr_decode": "قراءة رمز QR",
    "apk_manifest": "أذونات التطبيق وبياناته",
    "mobsf": "التحليل المتعمق (MobSF)",
}


def translate_finding(finding: FindingData) -> bool:
    """Rewrites the finding in Arabic in place. Returns False if it is not covered."""
    for entry in CATALOGUE:
        match = entry.pattern.match(finding.title)
        if match:
            finding.title = entry.title(match)
            finding.explanation = entry.explanation
            return True
    return False


def translate_check(check: Check) -> None:
    check.label = CHECK_LABELS_AR.get(check.key, check.label)
