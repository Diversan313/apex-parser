"""Справочник континентов: ISO-коды стран → континент.

Лёгкая статичная таблица для разбивки подписок по континентам
(subs/other/continents/). Названия папок — верхним регистром
через подчёркивание: NORTH_AMERICA, SOUTH_AMERICA.
"""
from __future__ import annotations

CONTINENTS: dict[str, frozenset] = {
    "EUROPE": frozenset(
        "AD AL AT BA BE BG BY CH CY CZ DE DK EE ES FI FO FR GB GG GI GR "
        "HR HU IE IM IS IT JE LI LT LU LV MC MD ME MK MT NL NO PL PT RO "
        "RS RU SE SI SJ SK SM UA VA XK".split()
    ),
    "ASIA": frozenset(
        "AE AF AM AZ BD BN BT CN GE HK ID IL IN IQ IR JO JP KG KH KP KR "
        "KZ LA LB LK MM MN MO MV MY NP OM PH PK PS QA SA SG SY TH TJ TL "
        "TR TW UZ VN YE".split()
    ),
    "AFRICA": frozenset(
        "AO BF BI BJ BW CD CF CG CI CM CV DJ DZ EG EH ER ET GA GH GM GN "
        "GQ GW KE KM LR LS LY MA MG ML MR MU MW MZ NA NE NG RE RW SC SD "
        "SL SN SO SS ST SZ TD TG TN TZ UG YT ZA ZM ZW".split()
    ),
    "NORTH_AMERICA": frozenset(
        "AG AI AW BB BL BM BQ BS BZ CA CR CU CW DM DO GD GL GP GT HN HT "
        "JM KN KY LC MF MQ MS MX NI PA PM PR SV SX TC TT US VC VG VI".split()
    ),
    "SOUTH_AMERICA": frozenset(
        "AR BO BR CL CO EC FK GF GY PE PY SR UY VE".split()
    ),
    "OCEANIA": frozenset(
        "AS AU CK FJ FM GU KI MH MP NC NF NR NU NZ PF PG PN PW SB TK TO "
        "TV VU WF WS".split()
    ),
}

# Обратный индекс: ISO-код → континент
_CC_TO_CONTINENT: dict[str, str] = {
    cc: continent
    for continent, codes in CONTINENTS.items()
    for cc in codes
}


def continent_for_cc(cc: str) -> str | None:
    """ISO-код страны → имя континента (или None, если не знаем)."""
    if not cc:
        return None
    return _CC_TO_CONTINENT.get(str(cc).strip().upper())
