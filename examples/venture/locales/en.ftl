# The example venture's strings (issue #190).
#
# A Fluent message per notification, with a `.title` and a `.body` — and
# optionally a `.subject`, which only mail reads. `{ $name }` is a
# placeable the caller passes in `args`.
#
# Money and dates are NOT formatted here: the money rules say a venture
# passes an already-formatted string, because only it knows the currency,
# the scale and how it rounds.

booking-confirmed =
    .title = Booking confirmed
    .body = { $places ->
        [one] One place with { $coach }, on { $day }
       *[other] { $places } places with { $coach }, on { $day }
    }
    .subject = Your booking with { $coach }

room-starting =
    .title = Your room starts soon
    .body = { $room } starts in { $minutes ->
        [one] a minute
       *[other] { $minutes } minutes
    }
