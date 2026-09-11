# Bahasa Indonesia. Indonesian has one plural form, so `[one]` never
# appears: `*[other]` answers for every count, which is what the CLDR
# rules `intl_pluralrules` ships say and what makes Fluent worth having.

booking-confirmed =
    .title = Pesanan dikonfirmasi
    .body = { $places } tempat bersama { $coach }, pada { $day }
    .subject = Pesanan Anda bersama { $coach }

room-starting =
    .title = Kelas Anda segera dimulai
    .body = { $room } dimulai dalam { $minutes } menit
