/*
 * This software is Copyright (c) 2018-2020 magnum
 * and is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */
#include <stddef.h>
#include <stdint.h>

#include "unicode.h"

size_t full_unicode_charset(UTF32* charset)
{
	int i, c;

/*
 * This defines the character set. This is auto-generated from UnicodeData.txt
 * of Unicode 13.0.0 and we skip control characters.
 */
	i = 0;
// 0000..007F; Basic Latin
	c = 0x20;		// from SPACE
	while (c <= 0x7e)	// ..to TILDE
		charset[i++] = c++;
// 0080..00FF; Latin-1 Supplement
	c = 0xa0;		// from NO-BREAK SPACE
	while (c <= 0xff)	// ..to LATIN SMALL LETTER Y WITH DIAERESIS
		charset[i++] = c++;
// 0100..017F; Latin Extended-A
	c = 0x100;		// from LATIN CAPITAL LETTER A WITH MACRON
	while (c <= 0x17f)	// ..to LATIN SMALL LETTER LONG S
		charset[i++] = c++;
// 0180..024F; Latin Extended-B
	c = 0x180;		// from LATIN SMALL LETTER B WITH STROKE
	while (c <= 0x24f)	// ..to LATIN SMALL LETTER Y WITH STROKE
		charset[i++] = c++;
// 0250..02AF; IPA Extensions
	c = 0x250;		// from LATIN SMALL LETTER TURNED A
	while (c <= 0x2af)	// ..to LATIN SMALL LETTER TURNED H WITH FISHHOOK AND TAIL
		charset[i++] = c++;
// 02B0..02FF; Spacing Modifier Letters
	c = 0x2b0;		// from MODIFIER LETTER SMALL H
	while (c <= 0x2ff)	// ..to MODIFIER LETTER LOW LEFT ARROW
		charset[i++] = c++;
// 0300..036F; Combining Diacritical Marks
	c = 0x300;		// from COMBINING GRAVE ACCENT
	while (c <= 0x36f)	// ..to COMBINING LATIN SMALL LETTER X
		charset[i++] = c++;
// 0370..03FF; Greek and Coptic
	c = 0x370;		// from GREEK CAPITAL LETTER HETA
	while (c <= 0x377)	// ..to GREEK SMALL LETTER PAMPHYLIAN DIGAMMA
		charset[i++] = c++;
	c = 0x37a;		// from GREEK YPOGEGRAMMENI
	while (c <= 0x37f)	// ..to GREEK CAPITAL LETTER YOT
		charset[i++] = c++;
	c = 0x384;		// from GREEK TONOS
	while (c <= 0x38a)	// ..to GREEK CAPITAL LETTER IOTA WITH TONOS
		charset[i++] = c++;
	c = 0x38e;		// from GREEK CAPITAL LETTER UPSILON WITH TONOS
	while (c <= 0x3a1)	// ..to GREEK CAPITAL LETTER RHO
		charset[i++] = c++;
	c = 0x3a3;		// from GREEK CAPITAL LETTER SIGMA
	while (c <= 0x3ff)	// ..to GREEK CAPITAL REVERSED DOTTED LUNATE SIGMA SYMBOL
		charset[i++] = c++;
// 0400..04FF; Cyrillic
	c = 0x400;		// from CYRILLIC CAPITAL LETTER IE WITH GRAVE
	while (c <= 0x4ff)	// ..to CYRILLIC SMALL LETTER HA WITH STROKE
		charset[i++] = c++;
// 0500..052F; Cyrillic Supplement
	c = 0x500;		// from CYRILLIC CAPITAL LETTER KOMI DE
	while (c <= 0x52f)	// ..to CYRILLIC SMALL LETTER EL WITH DESCENDER
		charset[i++] = c++;
// 0530..058F; Armenian
	c = 0x531;		// from ARMENIAN CAPITAL LETTER AYB
	while (c <= 0x556)	// ..to ARMENIAN CAPITAL LETTER FEH
		charset[i++] = c++;
	c = 0x559;		// from ARMENIAN MODIFIER LETTER LEFT HALF RING
	while (c <= 0x58a)	// ..to ARMENIAN HYPHEN
		charset[i++] = c++;
	charset[i++] = 0x58d;	// RIGHT-FACING ARMENIAN ETERNITY SIGN
	charset[i++] = 0x58f;	// ARMENIAN DRAM SIGN
// 0590..05FF; Hebrew
	c = 0x591;		// from HEBREW ACCENT ETNAHTA
	while (c <= 0x5c7)	// ..to HEBREW POINT QAMATS QATAN
		charset[i++] = c++;
	c = 0x5d0;		// from HEBREW LETTER ALEF
	while (c <= 0x5ea)	// ..to HEBREW LETTER TAV
		charset[i++] = c++;
	c = 0x5ef;		// from HEBREW YOD TRIANGLE
	while (c <= 0x5f4)	// ..to HEBREW PUNCTUATION GERSHAYIM
		charset[i++] = c++;
// 0600..06FF; Arabic
	c = 0x600;		// from ARABIC NUMBER SIGN
	while (c <= 0x61c)	// ..to ARABIC LETTER MARK
		charset[i++] = c++;
	c = 0x61e;		// from ARABIC TRIPLE DOT PUNCTUATION MARK
	while (c <= 0x6ff)	// ..to ARABIC LETTER HEH WITH INVERTED V
		charset[i++] = c++;
// 0700..074F; Syriac
	c = 0x700;		// from SYRIAC END OF PARAGRAPH
	while (c <= 0x70d)	// ..to SYRIAC HARKLEAN ASTERISCUS
		charset[i++] = c++;
	c = 0x70f;		// from SYRIAC ABBREVIATION MARK
	while (c <= 0x74a)	// ..to SYRIAC BARREKH
		charset[i++] = c++;
	charset[i++] = 0x74d;	// SYRIAC LETTER SOGDIAN ZHAIN
	charset[i++] = 0x74f;	// SYRIAC LETTER SOGDIAN FE
// 0750..077F; Arabic Supplement
	c = 0x750;		// from ARABIC LETTER BEH WITH THREE DOTS HORIZONTALLY BELOW
	while (c <= 0x77f)	// ..to ARABIC LETTER KAF WITH TWO DOTS ABOVE
		charset[i++] = c++;
// 0780..07BF; Thaana
	c = 0x780;		// from THAANA LETTER HAA
	while (c <= 0x7b1)	// ..to THAANA LETTER NAA
		charset[i++] = c++;
// 07C0..07FF; NKo
	c = 0x7c0;		// from NKO DIGIT ZERO
	while (c <= 0x7fa)	// ..to NKO LAJANYALAN
		charset[i++] = c++;
	charset[i++] = 0x7fd;	// NKO DANTAYALAN
	charset[i++] = 0x7ff;	// NKO TAMAN SIGN
// 0800..083F; Samaritan
	c = 0x800;		// from SAMARITAN LETTER ALAF
	while (c <= 0x82d)	// ..to SAMARITAN MARK NEQUDAA
		charset[i++] = c++;
	c = 0x830;		// from SAMARITAN PUNCTUATION NEQUDAA
	while (c <= 0x83e)	// ..to SAMARITAN PUNCTUATION ANNAAU
		charset[i++] = c++;
// 0840..085F; Mandaic
	c = 0x840;		// from MANDAIC LETTER HALQA
	while (c <= 0x85b)	// ..to MANDAIC GEMINATION MARK
		charset[i++] = c++;
	charset[i++] = 0x85e;	// MANDAIC PUNCTUATION
// 0860..086F; Syriac Supplement
	c = 0x860;		// from SYRIAC LETTER MALAYALAM NGA
	while (c <= 0x86a)	// ..to SYRIAC LETTER MALAYALAM SSA
		charset[i++] = c++;
// 08A0..08FF; Arabic Extended-A
	c = 0x8a0;		// from ARABIC LETTER BEH WITH SMALL V BELOW
	while (c <= 0x8b4)	// ..to ARABIC LETTER KAF WITH DOT BELOW
		charset[i++] = c++;
	c = 0x8b6;		// from ARABIC LETTER BEH WITH SMALL MEEM ABOVE
	while (c <= 0x8c7)	// ..to ARABIC LETTER LAM WITH SMALL ARABIC LETTER TAH ABOVE
		charset[i++] = c++;
	c = 0x8d3;		// from ARABIC SMALL LOW WAW
	while (c <= 0x8ff)	// ..to ARABIC MARK SIDEWAYS NOON GHUNNA
		charset[i++] = c++;
// 0900..097F; Devanagari
	c = 0x900;		// from DEVANAGARI SIGN INVERTED CANDRABINDU
	while (c <= 0x97f)	// ..to DEVANAGARI LETTER BBA
		charset[i++] = c++;
// 0980..09FF; Bengali
	c = 0x980;		// from BENGALI ANJI
	while (c <= 0x983)	// ..to BENGALI SIGN VISARGA
		charset[i++] = c++;
	c = 0x985;		// from BENGALI LETTER A
	while (c <= 0x98c)	// ..to BENGALI LETTER VOCALIC L
		charset[i++] = c++;
	charset[i++] = 0x98f;	// BENGALI LETTER E
	charset[i++] = 0x990;	// BENGALI LETTER AI
	c = 0x993;		// from BENGALI LETTER O
	while (c <= 0x9a8)	// ..to BENGALI LETTER NA
		charset[i++] = c++;
	c = 0x9aa;		// from BENGALI LETTER PA
	while (c <= 0x9b0)	// ..to BENGALI LETTER RA
		charset[i++] = c++;
	c = 0x9b6;		// from BENGALI LETTER SHA
	while (c <= 0x9b9)	// ..to BENGALI LETTER HA
		charset[i++] = c++;
	c = 0x9bc;		// from BENGALI SIGN NUKTA
	while (c <= 0x9c4)	// ..to BENGALI VOWEL SIGN VOCALIC RR
		charset[i++] = c++;
	charset[i++] = 0x9c7;	// BENGALI VOWEL SIGN E
	charset[i++] = 0x9c8;	// BENGALI VOWEL SIGN AI
	c = 0x9cb;		// from BENGALI VOWEL SIGN O
	while (c <= 0x9ce)	// ..to BENGALI LETTER KHANDA TA
		charset[i++] = c++;
	charset[i++] = 0x9dc;	// BENGALI LETTER RRA
	charset[i++] = 0x9dd;	// BENGALI LETTER RHA
	c = 0x9df;		// from BENGALI LETTER YYA
	while (c <= 0x9e3)	// ..to BENGALI VOWEL SIGN VOCALIC LL
		charset[i++] = c++;
	c = 0x9e6;		// from BENGALI DIGIT ZERO
	while (c <= 0x9fe)	// ..to BENGALI SANDHI MARK
		charset[i++] = c++;
// 0A00..0A7F; Gurmukhi
	charset[i++] = 0xa01;	// GURMUKHI SIGN ADAK BINDI
	charset[i++] = 0xa03;	// GURMUKHI SIGN VISARGA
	c = 0xa05;		// from GURMUKHI LETTER A
	while (c <= 0xa0a)	// ..to GURMUKHI LETTER UU
		charset[i++] = c++;
	charset[i++] = 0xa0f;	// GURMUKHI LETTER EE
	charset[i++] = 0xa10;	// GURMUKHI LETTER AI
	c = 0xa13;		// from GURMUKHI LETTER OO
	while (c <= 0xa28)	// ..to GURMUKHI LETTER NA
		charset[i++] = c++;
	c = 0xa2a;		// from GURMUKHI LETTER PA
	while (c <= 0xa30)	// ..to GURMUKHI LETTER RA
		charset[i++] = c++;
	charset[i++] = 0xa32;	// GURMUKHI LETTER LA
	charset[i++] = 0xa33;	// GURMUKHI LETTER LLA
	charset[i++] = 0xa35;	// GURMUKHI LETTER VA
	charset[i++] = 0xa36;	// GURMUKHI LETTER SHA
	charset[i++] = 0xa38;	// GURMUKHI LETTER SA
	charset[i++] = 0xa39;	// GURMUKHI LETTER HA
	c = 0xa3e;		// from GURMUKHI VOWEL SIGN AA
	while (c <= 0xa42)	// ..to GURMUKHI VOWEL SIGN UU
		charset[i++] = c++;
	charset[i++] = 0xa47;	// GURMUKHI VOWEL SIGN EE
	charset[i++] = 0xa48;	// GURMUKHI VOWEL SIGN AI
	charset[i++] = 0xa4b;	// GURMUKHI VOWEL SIGN OO
	charset[i++] = 0xa4d;	// GURMUKHI SIGN VIRAMA
	c = 0xa59;		// from GURMUKHI LETTER KHHA
	while (c <= 0xa5c)	// ..to GURMUKHI LETTER RRA
		charset[i++] = c++;
	c = 0xa66;		// from GURMUKHI DIGIT ZERO
	while (c <= 0xa76)	// ..to GURMUKHI ABBREVIATION SIGN
		charset[i++] = c++;
// 0A80..0AFF; Gujarati
	charset[i++] = 0xa81;	// GUJARATI SIGN CANDRABINDU
	charset[i++] = 0xa83;	// GUJARATI SIGN VISARGA
	c = 0xa85;		// from GUJARATI LETTER A
	while (c <= 0xa8d)	// ..to GUJARATI VOWEL CANDRA E
		charset[i++] = c++;
	charset[i++] = 0xa8f;	// GUJARATI LETTER E
	charset[i++] = 0xa91;	// GUJARATI VOWEL CANDRA O
	c = 0xa93;		// from GUJARATI LETTER O
	while (c <= 0xaa8)	// ..to GUJARATI LETTER NA
		charset[i++] = c++;
	c = 0xaaa;		// from GUJARATI LETTER PA
	while (c <= 0xab0)	// ..to GUJARATI LETTER RA
		charset[i++] = c++;
	charset[i++] = 0xab2;	// GUJARATI LETTER LA
	charset[i++] = 0xab3;	// GUJARATI LETTER LLA
	c = 0xab5;		// from GUJARATI LETTER VA
	while (c <= 0xab9)	// ..to GUJARATI LETTER HA
		charset[i++] = c++;
	c = 0xabc;		// from GUJARATI SIGN NUKTA
	while (c <= 0xac5)	// ..to GUJARATI VOWEL SIGN CANDRA E
		charset[i++] = c++;
	charset[i++] = 0xac7;	// GUJARATI VOWEL SIGN E
	charset[i++] = 0xac9;	// GUJARATI VOWEL SIGN CANDRA O
	charset[i++] = 0xacb;	// GUJARATI VOWEL SIGN O
	charset[i++] = 0xacd;	// GUJARATI SIGN VIRAMA
	c = 0xae0;		// from GUJARATI LETTER VOCALIC RR
	while (c <= 0xae3)	// ..to GUJARATI VOWEL SIGN VOCALIC LL
		charset[i++] = c++;
	c = 0xae6;		// from GUJARATI DIGIT ZERO
	while (c <= 0xaf1)	// ..to GUJARATI RUPEE SIGN
		charset[i++] = c++;
	c = 0xaf9;		// from GUJARATI LETTER ZHA
	while (c <= 0xaff)	// ..to GUJARATI SIGN TWO-CIRCLE NUKTA ABOVE
		charset[i++] = c++;
// 0B00..0B7F; Oriya
	charset[i++] = 0xb01;	// ORIYA SIGN CANDRABINDU
	charset[i++] = 0xb03;	// ORIYA SIGN VISARGA
	c = 0xb05;		// from ORIYA LETTER A
	while (c <= 0xb0c)	// ..to ORIYA LETTER VOCALIC L
		charset[i++] = c++;
	charset[i++] = 0xb0f;	// ORIYA LETTER E
	charset[i++] = 0xb10;	// ORIYA LETTER AI
	c = 0xb13;		// from ORIYA LETTER O
	while (c <= 0xb28)	// ..to ORIYA LETTER NA
		charset[i++] = c++;
	c = 0xb2a;		// from ORIYA LETTER PA
	while (c <= 0xb30)	// ..to ORIYA LETTER RA
		charset[i++] = c++;
	charset[i++] = 0xb32;	// ORIYA LETTER LA
	charset[i++] = 0xb33;	// ORIYA LETTER LLA
	c = 0xb35;		// from ORIYA LETTER VA
	while (c <= 0xb39)	// ..to ORIYA LETTER HA
		charset[i++] = c++;
	c = 0xb3c;		// from ORIYA SIGN NUKTA
	while (c <= 0xb44)	// ..to ORIYA VOWEL SIGN VOCALIC RR
		charset[i++] = c++;
	charset[i++] = 0xb47;	// ORIYA VOWEL SIGN E
	charset[i++] = 0xb48;	// ORIYA VOWEL SIGN AI
	charset[i++] = 0xb4b;	// ORIYA VOWEL SIGN O
	charset[i++] = 0xb4d;	// ORIYA SIGN VIRAMA
	charset[i++] = 0xb55;	// ORIYA SIGN OVERLINE
	charset[i++] = 0xb57;	// ORIYA AU LENGTH MARK
	charset[i++] = 0xb5c;	// ORIYA LETTER RRA
	charset[i++] = 0xb5d;	// ORIYA LETTER RHA
	c = 0xb5f;		// from ORIYA LETTER YYA
	while (c <= 0xb63)	// ..to ORIYA VOWEL SIGN VOCALIC LL
		charset[i++] = c++;
	c = 0xb66;		// from ORIYA DIGIT ZERO
	while (c <= 0xb77)	// ..to ORIYA FRACTION THREE SIXTEENTHS
		charset[i++] = c++;
// 0B80..0BFF; Tamil
	charset[i++] = 0xb82;	// TAMIL SIGN ANUSVARA
	charset[i++] = 0xb83;	// TAMIL SIGN VISARGA
	c = 0xb85;		// from TAMIL LETTER A
	while (c <= 0xb8a)	// ..to TAMIL LETTER UU
		charset[i++] = c++;
	charset[i++] = 0xb8e;	// TAMIL LETTER E
	charset[i++] = 0xb90;	// TAMIL LETTER AI
	c = 0xb92;		// from TAMIL LETTER O
	while (c <= 0xb95)	// ..to TAMIL LETTER KA
		charset[i++] = c++;
	charset[i++] = 0xb99;	// TAMIL LETTER NGA
	charset[i++] = 0xb9a;	// TAMIL LETTER CA
	charset[i++] = 0xb9e;	// TAMIL LETTER NYA
	charset[i++] = 0xb9f;	// TAMIL LETTER TTA
	charset[i++] = 0xba3;	// TAMIL LETTER NNA
	charset[i++] = 0xba4;	// TAMIL LETTER TA
	charset[i++] = 0xba8;	// TAMIL LETTER NA
	charset[i++] = 0xbaa;	// TAMIL LETTER PA
	c = 0xbae;		// from TAMIL LETTER MA
	while (c <= 0xbb9)	// ..to TAMIL LETTER HA
		charset[i++] = c++;
	c = 0xbbe;		// from TAMIL VOWEL SIGN AA
	while (c <= 0xbc2)	// ..to TAMIL VOWEL SIGN UU
		charset[i++] = c++;
	charset[i++] = 0xbc6;	// TAMIL VOWEL SIGN E
	charset[i++] = 0xbc8;	// TAMIL VOWEL SIGN AI
	c = 0xbca;		// from TAMIL VOWEL SIGN O
	while (c <= 0xbcd)	// ..to TAMIL SIGN VIRAMA
		charset[i++] = c++;
	c = 0xbe6;		// from TAMIL DIGIT ZERO
	while (c <= 0xbfa)	// ..to TAMIL NUMBER SIGN
		charset[i++] = c++;
// 0C00..0C7F; Telugu
	c = 0xc00;		// from TELUGU SIGN COMBINING CANDRABINDU ABOVE
	while (c <= 0xc0c)	// ..to TELUGU LETTER VOCALIC L
		charset[i++] = c++;
	charset[i++] = 0xc0e;	// TELUGU LETTER E
	charset[i++] = 0xc10;	// TELUGU LETTER AI
	c = 0xc12;		// from TELUGU LETTER O
	while (c <= 0xc28)	// ..to TELUGU LETTER NA
		charset[i++] = c++;
	c = 0xc2a;		// from TELUGU LETTER PA
	while (c <= 0xc39)	// ..to TELUGU LETTER HA
		charset[i++] = c++;
	c = 0xc3d;		// from TELUGU SIGN AVAGRAHA
	while (c <= 0xc44)	// ..to TELUGU VOWEL SIGN VOCALIC RR
		charset[i++] = c++;
	charset[i++] = 0xc46;	// TELUGU VOWEL SIGN E
	charset[i++] = 0xc48;	// TELUGU VOWEL SIGN AI
	c = 0xc4a;		// from TELUGU VOWEL SIGN O
	while (c <= 0xc4d)	// ..to TELUGU SIGN VIRAMA
		charset[i++] = c++;
	charset[i++] = 0xc55;	// TELUGU LENGTH MARK
	charset[i++] = 0xc56;	// TELUGU AI LENGTH MARK
	charset[i++] = 0xc58;	// TELUGU LETTER TSA
	charset[i++] = 0xc5a;	// TELUGU LETTER RRRA
	c = 0xc60;		// from TELUGU LETTER VOCALIC RR
	while (c <= 0xc63)	// ..to TELUGU VOWEL SIGN VOCALIC LL
		charset[i++] = c++;
	c = 0xc66;		// from TELUGU DIGIT ZERO
	while (c <= 0xc6f)	// ..to TELUGU DIGIT NINE
		charset[i++] = c++;
	c = 0xc77;		// from TELUGU SIGN SIDDHAM
	while (c <= 0xc7f)	// ..to TELUGU SIGN TUUMU
		charset[i++] = c++;
// 0C80..0CFF; Kannada
	c = 0xc80;		// from KANNADA SIGN SPACING CANDRABINDU
	while (c <= 0xc8c)	// ..to KANNADA LETTER VOCALIC L
		charset[i++] = c++;
	charset[i++] = 0xc8e;	// KANNADA LETTER E
	charset[i++] = 0xc90;	// KANNADA LETTER AI
	c = 0xc92;		// from KANNADA LETTER O
	while (c <= 0xca8)	// ..to KANNADA LETTER NA
		charset[i++] = c++;
	c = 0xcaa;		// from KANNADA LETTER PA
	while (c <= 0xcb3)	// ..to KANNADA LETTER LLA
		charset[i++] = c++;
	c = 0xcb5;		// from KANNADA LETTER VA
	while (c <= 0xcb9)	// ..to KANNADA LETTER HA
		charset[i++] = c++;
	c = 0xcbc;		// from KANNADA SIGN NUKTA
	while (c <= 0xcc4)	// ..to KANNADA VOWEL SIGN VOCALIC RR
		charset[i++] = c++;
	charset[i++] = 0xcc6;	// KANNADA VOWEL SIGN E
	charset[i++] = 0xcc8;	// KANNADA VOWEL SIGN AI
	c = 0xcca;		// from KANNADA VOWEL SIGN O
	while (c <= 0xccd)	// ..to KANNADA SIGN VIRAMA
		charset[i++] = c++;
	charset[i++] = 0xcd5;	// KANNADA LENGTH MARK
	charset[i++] = 0xcd6;	// KANNADA AI LENGTH MARK
	c = 0xce0;		// from KANNADA LETTER VOCALIC RR
	while (c <= 0xce3)	// ..to KANNADA VOWEL SIGN VOCALIC LL
		charset[i++] = c++;
	c = 0xce6;		// from KANNADA DIGIT ZERO
	while (c <= 0xcef)	// ..to KANNADA DIGIT NINE
		charset[i++] = c++;
	charset[i++] = 0xcf1;	// KANNADA SIGN JIHVAMULIYA
	charset[i++] = 0xcf2;	// KANNADA SIGN UPADHMANIYA
// 0D00..0D7F; Malayalam
	c = 0xd00;		// from MALAYALAM SIGN COMBINING ANUSVARA ABOVE
	while (c <= 0xd0c)	// ..to MALAYALAM LETTER VOCALIC L
		charset[i++] = c++;
	charset[i++] = 0xd0e;	// MALAYALAM LETTER E
	charset[i++] = 0xd10;	// MALAYALAM LETTER AI
	c = 0xd12;		// from MALAYALAM LETTER O
	while (c <= 0xd44)	// ..to MALAYALAM VOWEL SIGN VOCALIC RR
		charset[i++] = c++;
	charset[i++] = 0xd46;	// MALAYALAM VOWEL SIGN E
	charset[i++] = 0xd48;	// MALAYALAM VOWEL SIGN AI
	c = 0xd4a;		// from MALAYALAM VOWEL SIGN O
	while (c <= 0xd4f)	// ..to MALAYALAM SIGN PARA
		charset[i++] = c++;
	c = 0xd54;		// from MALAYALAM LETTER CHILLU M
	while (c <= 0xd63)	// ..to MALAYALAM VOWEL SIGN VOCALIC LL
		charset[i++] = c++;
	c = 0xd66;		// from MALAYALAM DIGIT ZERO
	while (c <= 0xd7f)	// ..to MALAYALAM LETTER CHILLU K
		charset[i++] = c++;
// 0D80..0DFF; Sinhala
	charset[i++] = 0xd81;	// SINHALA SIGN CANDRABINDU
	charset[i++] = 0xd83;	// SINHALA SIGN VISARGAYA
	c = 0xd85;		// from SINHALA LETTER AYANNA
	while (c <= 0xd96)	// ..to SINHALA LETTER AUYANNA
		charset[i++] = c++;
	c = 0xd9a;		// from SINHALA LETTER ALPAPRAANA KAYANNA
	while (c <= 0xdb1)	// ..to SINHALA LETTER DANTAJA NAYANNA
		charset[i++] = c++;
	c = 0xdb3;		// from SINHALA LETTER SANYAKA DAYANNA
	while (c <= 0xdbb)	// ..to SINHALA LETTER RAYANNA
		charset[i++] = c++;
	c = 0xdc0;		// from SINHALA LETTER VAYANNA
	while (c <= 0xdc6)	// ..to SINHALA LETTER FAYANNA
		charset[i++] = c++;
	c = 0xdcf;		// from SINHALA VOWEL SIGN AELA-PILLA
	while (c <= 0xdd4)	// ..to SINHALA VOWEL SIGN KETTI PAA-PILLA
		charset[i++] = c++;
	c = 0xdd8;		// from SINHALA VOWEL SIGN GAETTA-PILLA
	while (c <= 0xddf)	// ..to SINHALA VOWEL SIGN GAYANUKITTA
		charset[i++] = c++;
	c = 0xde6;		// from SINHALA LITH DIGIT ZERO
	while (c <= 0xdef)	// ..to SINHALA LITH DIGIT NINE
		charset[i++] = c++;
	charset[i++] = 0xdf2;	// SINHALA VOWEL SIGN DIGA GAETTA-PILLA
	charset[i++] = 0xdf4;	// SINHALA PUNCTUATION KUNDDALIYA
// 0E00..0E7F; Thai
	c = 0xe01;		// from THAI CHARACTER KO KAI
	while (c <= 0xe3a)	// ..to THAI CHARACTER PHINTHU
		charset[i++] = c++;
	c = 0xe3f;		// from THAI CURRENCY SYMBOL BAHT
	while (c <= 0xe5b)	// ..to THAI CHARACTER KHOMUT
		charset[i++] = c++;
// 0E80..0EFF; Lao
	charset[i++] = 0xe81;	// LAO LETTER KO
	charset[i++] = 0xe82;	// LAO LETTER KHO SUNG
	c = 0xe86;		// from LAO LETTER PALI GHA
	while (c <= 0xe8a)	// ..to LAO LETTER SO TAM
		charset[i++] = c++;
	c = 0xe8c;		// from LAO LETTER PALI JHA
	while (c <= 0xea3)	// ..to LAO LETTER LO LING
		charset[i++] = c++;
	c = 0xea7;		// from LAO LETTER WO
	while (c <= 0xebd)	// ..to LAO SEMIVOWEL SIGN NYO
		charset[i++] = c++;
	c = 0xec0;		// from LAO VOWEL SIGN E
	while (c <= 0xec4)	// ..to LAO VOWEL SIGN AI
		charset[i++] = c++;
	c = 0xec8;		// from LAO TONE MAI EK
	while (c <= 0xecd)	// ..to LAO NIGGAHITA
		charset[i++] = c++;
	c = 0xed0;		// from LAO DIGIT ZERO
	while (c <= 0xed9)	// ..to LAO DIGIT NINE
		charset[i++] = c++;
	c = 0xedc;		// from LAO HO NO
	while (c <= 0xedf)	// ..to LAO LETTER KHMU NYO
		charset[i++] = c++;
// 0F00..0FFF; Tibetan
	c = 0xf00;		// from TIBETAN SYLLABLE OM
	while (c <= 0xf47)	// ..to TIBETAN LETTER JA
		charset[i++] = c++;
	c = 0xf49;		// from TIBETAN LETTER NYA
	while (c <= 0xf6c)	// ..to TIBETAN LETTER RRA
		charset[i++] = c++;
	c = 0xf71;		// from TIBETAN VOWEL SIGN AA
	while (c <= 0xf97)	// ..to TIBETAN SUBJOINED LETTER JA
		charset[i++] = c++;
	c = 0xf99;		// from TIBETAN SUBJOINED LETTER NYA
	while (c <= 0xfbc)	// ..to TIBETAN SUBJOINED LETTER FIXED-FORM RA
		charset[i++] = c++;
	c = 0xfbe;		// from TIBETAN KU RU KHA
	while (c <= 0xfcc)	// ..to TIBETAN SYMBOL NOR BU BZHI -KHYIL
		charset[i++] = c++;
	c = 0xfce;		// from TIBETAN SIGN RDEL NAG RDEL DKAR
	while (c <= 0xfda)	// ..to TIBETAN MARK TRAILING MCHAN RTAGS
		charset[i++] = c++;
// 1000..109F; Myanmar
	c = 0x1000;		// from MYANMAR LETTER KA
	while (c <= 0x109f)	// ..to MYANMAR SYMBOL SHAN EXCLAMATION
		charset[i++] = c++;
// 10A0..10FF; Georgian
	c = 0x10a0;		// from GEORGIAN CAPITAL LETTER AN
	while (c <= 0x10c5)	// ..to GEORGIAN CAPITAL LETTER HOE
		charset[i++] = c++;
	c = 0x10d0;		// from GEORGIAN LETTER AN
	while (c <= 0x10ff)	// ..to GEORGIAN LETTER LABIAL SIGN
		charset[i++] = c++;
// 1100..11FF; Hangul Jamo
	c = 0x1100;		// from HANGUL CHOSEONG KIYEOK
	while (c <= 0x11ff)	// ..to HANGUL JONGSEONG SSANGNIEUN
		charset[i++] = c++;
// 1200..137F; Ethiopic
	c = 0x1200;		// from ETHIOPIC SYLLABLE HA
	while (c <= 0x1248)	// ..to ETHIOPIC SYLLABLE QWA
		charset[i++] = c++;
	c = 0x124a;		// from ETHIOPIC SYLLABLE QWI
	while (c <= 0x124d)	// ..to ETHIOPIC SYLLABLE QWE
		charset[i++] = c++;
	c = 0x1250;		// from ETHIOPIC SYLLABLE QHA
	while (c <= 0x1256)	// ..to ETHIOPIC SYLLABLE QHO
		charset[i++] = c++;
	c = 0x125a;		// from ETHIOPIC SYLLABLE QHWI
	while (c <= 0x125d)	// ..to ETHIOPIC SYLLABLE QHWE
		charset[i++] = c++;
	c = 0x1260;		// from ETHIOPIC SYLLABLE BA
	while (c <= 0x1288)	// ..to ETHIOPIC SYLLABLE XWA
		charset[i++] = c++;
	c = 0x128a;		// from ETHIOPIC SYLLABLE XWI
	while (c <= 0x128d)	// ..to ETHIOPIC SYLLABLE XWE
		charset[i++] = c++;
	c = 0x1290;		// from ETHIOPIC SYLLABLE NA
	while (c <= 0x12b0)	// ..to ETHIOPIC SYLLABLE KWA
		charset[i++] = c++;
	c = 0x12b2;		// from ETHIOPIC SYLLABLE KWI
	while (c <= 0x12b5)	// ..to ETHIOPIC SYLLABLE KWE
		charset[i++] = c++;
	c = 0x12b8;		// from ETHIOPIC SYLLABLE KXA
	while (c <= 0x12be)	// ..to ETHIOPIC SYLLABLE KXO
		charset[i++] = c++;
	c = 0x12c2;		// from ETHIOPIC SYLLABLE KXWI
	while (c <= 0x12c5)	// ..to ETHIOPIC SYLLABLE KXWE
		charset[i++] = c++;
	c = 0x12c8;		// from ETHIOPIC SYLLABLE WA
	while (c <= 0x12d6)	// ..to ETHIOPIC SYLLABLE PHARYNGEAL O
		charset[i++] = c++;
	c = 0x12d8;		// from ETHIOPIC SYLLABLE ZA
	while (c <= 0x1310)	// ..to ETHIOPIC SYLLABLE GWA
		charset[i++] = c++;
	c = 0x1312;		// from ETHIOPIC SYLLABLE GWI
	while (c <= 0x1315)	// ..to ETHIOPIC SYLLABLE GWE
		charset[i++] = c++;
	c = 0x1318;		// from ETHIOPIC SYLLABLE GGA
	while (c <= 0x135a)	// ..to ETHIOPIC SYLLABLE FYA
		charset[i++] = c++;
	c = 0x135d;		// from ETHIOPIC COMBINING GEMINATION AND VOWEL LENGTH MARK
	while (c <= 0x137c)	// ..to ETHIOPIC NUMBER TEN THOUSAND
		charset[i++] = c++;
// 1380..139F; Ethiopic Supplement
	c = 0x1380;		// from ETHIOPIC SYLLABLE SEBATBEIT MWA
	while (c <= 0x1399)	// ..to ETHIOPIC TONAL MARK KURT
		charset[i++] = c++;
// 13A0..13FF; Cherokee
	c = 0x13a0;		// from CHEROKEE LETTER A
	while (c <= 0x13f5)	// ..to CHEROKEE LETTER MV
		charset[i++] = c++;
	c = 0x13f8;		// from CHEROKEE SMALL LETTER YE
	while (c <= 0x13fd)	// ..to CHEROKEE SMALL LETTER MV
		charset[i++] = c++;
// 1400..167F; Unified Canadian Aboriginal Syllabics
	c = 0x1400;		// from CANADIAN SYLLABICS HYPHEN
	while (c <= 0x167f)	// ..to CANADIAN SYLLABICS BLACKFOOT W
		charset[i++] = c++;
// 1680..169F; Ogham
	c = 0x1680;		// from OGHAM SPACE MARK
	while (c <= 0x169c)	// ..to OGHAM REVERSED FEATHER MARK
		charset[i++] = c++;
// 16A0..16FF; Runic
	c = 0x16a0;		// from RUNIC LETTER FEHU FEOH FE F
	while (c <= 0x16f8)	// ..to RUNIC LETTER FRANKS CASKET AESC
		charset[i++] = c++;
// 1700..171F; Tagalog
	c = 0x1700;		// from TAGALOG LETTER A
	while (c <= 0x170c)	// ..to TAGALOG LETTER YA
		charset[i++] = c++;
	c = 0x170e;		// from TAGALOG LETTER LA
	while (c <= 0x1714)	// ..to TAGALOG SIGN VIRAMA
		charset[i++] = c++;
// 1720..173F; Hanunoo
	c = 0x1720;		// from HANUNOO LETTER A
	while (c <= 0x1736)	// ..to PHILIPPINE DOUBLE PUNCTUATION
		charset[i++] = c++;
// 1740..175F; Buhid
	c = 0x1740;		// from BUHID LETTER A
	while (c <= 0x1753)	// ..to BUHID VOWEL SIGN U
		charset[i++] = c++;
// 1760..177F; Tagbanwa
	c = 0x1760;		// from TAGBANWA LETTER A
	while (c <= 0x176c)	// ..to TAGBANWA LETTER YA
		charset[i++] = c++;
	charset[i++] = 0x176e;	// TAGBANWA LETTER LA
	charset[i++] = 0x1770;	// TAGBANWA LETTER SA
	charset[i++] = 0x1772;	// TAGBANWA VOWEL SIGN I
	charset[i++] = 0x1773;	// TAGBANWA VOWEL SIGN U
// 1780..17FF; Khmer
	c = 0x1780;		// from KHMER LETTER KA
	while (c <= 0x17dd)	// ..to KHMER SIGN ATTHACAN
		charset[i++] = c++;
	c = 0x17e0;		// from KHMER DIGIT ZERO
	while (c <= 0x17e9)	// ..to KHMER DIGIT NINE
		charset[i++] = c++;
	c = 0x17f0;		// from KHMER SYMBOL LEK ATTAK SON
	while (c <= 0x17f9)	// ..to KHMER SYMBOL LEK ATTAK PRAM-BUON
		charset[i++] = c++;
// 1800..18AF; Mongolian
	c = 0x1800;		// from MONGOLIAN BIRGA
	while (c <= 0x180e)	// ..to MONGOLIAN VOWEL SEPARATOR
		charset[i++] = c++;
	c = 0x1810;		// from MONGOLIAN DIGIT ZERO
	while (c <= 0x1819)	// ..to MONGOLIAN DIGIT NINE
		charset[i++] = c++;
	c = 0x1820;		// from MONGOLIAN LETTER A
	while (c <= 0x1878)	// ..to MONGOLIAN LETTER CHA WITH TWO DOTS
		charset[i++] = c++;
	c = 0x1880;		// from MONGOLIAN LETTER ALI GALI ANUSVARA ONE
	while (c <= 0x18aa)	// ..to MONGOLIAN LETTER MANCHU ALI GALI LHA
		charset[i++] = c++;
// 18B0..18FF; Unified Canadian Aboriginal Syllabics Extended
	c = 0x18b0;		// from CANADIAN SYLLABICS OY
	while (c <= 0x18f5)	// ..to CANADIAN SYLLABICS CARRIER DENTAL S
		charset[i++] = c++;
// 1900..194F; Limbu
	c = 0x1900;		// from LIMBU VOWEL-CARRIER LETTER
	while (c <= 0x191e)	// ..to LIMBU LETTER TRA
		charset[i++] = c++;
	c = 0x1920;		// from LIMBU VOWEL SIGN A
	while (c <= 0x192b)	// ..to LIMBU SUBJOINED LETTER WA
		charset[i++] = c++;
	c = 0x1930;		// from LIMBU SMALL LETTER KA
	while (c <= 0x193b)	// ..to LIMBU SIGN SA-I
		charset[i++] = c++;
	c = 0x1944;		// from LIMBU EXCLAMATION MARK
	while (c <= 0x194f)	// ..to LIMBU DIGIT NINE
		charset[i++] = c++;
// 1950..197F; Tai Le
	c = 0x1950;		// from TAI LE LETTER KA
	while (c <= 0x196d)	// ..to TAI LE LETTER AI
		charset[i++] = c++;
	c = 0x1970;		// from TAI LE LETTER TONE-2
	while (c <= 0x1974)	// ..to TAI LE LETTER TONE-6
		charset[i++] = c++;
// 1980..19DF; New Tai Lue
	c = 0x1980;		// from NEW TAI LUE LETTER HIGH QA
	while (c <= 0x19ab)	// ..to NEW TAI LUE LETTER LOW SUA
		charset[i++] = c++;
	c = 0x19b0;		// from NEW TAI LUE VOWEL SIGN VOWEL SHORTENER
	while (c <= 0x19c9)	// ..to NEW TAI LUE TONE MARK-2
		charset[i++] = c++;
	c = 0x19d0;		// from NEW TAI LUE DIGIT ZERO
	while (c <= 0x19da)	// ..to NEW TAI LUE THAM DIGIT ONE
		charset[i++] = c++;
	charset[i++] = 0x19de;	// NEW TAI LUE SIGN LAE
	charset[i++] = 0x19df;	// NEW TAI LUE SIGN LAEV
// 19E0..19FF; Khmer Symbols
	c = 0x19e0;		// from KHMER SYMBOL PATHAMASAT
	while (c <= 0x19ff)	// ..to KHMER SYMBOL DAP-PRAM ROC
		charset[i++] = c++;
// 1A00..1A1F; Buginese
	c = 0x1a00;		// from BUGINESE LETTER KA
	while (c <= 0x1a1b)	// ..to BUGINESE VOWEL SIGN AE
		charset[i++] = c++;
	charset[i++] = 0x1a1e;	// BUGINESE PALLAWA
	charset[i++] = 0x1a1f;	// BUGINESE END OF SECTION
// 1A20..1AAF; Tai Tham
	c = 0x1a20;		// from TAI THAM LETTER HIGH KA
	while (c <= 0x1a5e)	// ..to TAI THAM CONSONANT SIGN SA
		charset[i++] = c++;
	c = 0x1a60;		// from TAI THAM SIGN SAKOT
	while (c <= 0x1a7c)	// ..to TAI THAM SIGN KHUEN-LUE KARAN
		charset[i++] = c++;
	c = 0x1a7f;		// from TAI THAM COMBINING CRYPTOGRAMMIC DOT
	while (c <= 0x1a89)	// ..to TAI THAM HORA DIGIT NINE
		charset[i++] = c++;
	c = 0x1a90;		// from TAI THAM THAM DIGIT ZERO
	while (c <= 0x1a99)	// ..to TAI THAM THAM DIGIT NINE
		charset[i++] = c++;
	c = 0x1aa0;		// from TAI THAM SIGN WIANG
	while (c <= 0x1aad)	// ..to TAI THAM SIGN CAANG
		charset[i++] = c++;
// 1AB0..1AFF; Combining Diacritical Marks Extended
	c = 0x1ab0;		// from COMBINING DOUBLED CIRCUMFLEX ACCENT
	while (c <= 0x1ac0)	// ..to COMBINING LATIN SMALL LETTER TURNED W BELOW
		charset[i++] = c++;
// 1B00..1B7F; Balinese
	c = 0x1b00;		// from BALINESE SIGN ULU RICEM
	while (c <= 0x1b4b)	// ..to BALINESE LETTER ASYURA SASAK
		charset[i++] = c++;
	c = 0x1b50;		// from BALINESE DIGIT ZERO
	while (c <= 0x1b7c)	// ..to BALINESE MUSICAL SYMBOL LEFT-HAND OPEN PING
		charset[i++] = c++;
// 1B80..1BBF; Sundanese
	c = 0x1b80;		// from SUNDANESE SIGN PANYECEK
	while (c <= 0x1bbf)	// ..to SUNDANESE LETTER FINAL M
		charset[i++] = c++;
// 1BC0..1BFF; Batak
	c = 0x1bc0;		// from BATAK LETTER A
	while (c <= 0x1bf3)	// ..to BATAK PANONGONAN
		charset[i++] = c++;
	c = 0x1bfc;		// from BATAK SYMBOL BINDU NA METEK
	while (c <= 0x1bff)	// ..to BATAK SYMBOL BINDU PANGOLAT
		charset[i++] = c++;
// 1C00..1C4F; Lepcha
	c = 0x1c00;		// from LEPCHA LETTER KA
	while (c <= 0x1c37)	// ..to LEPCHA SIGN NUKTA
		charset[i++] = c++;
	c = 0x1c3b;		// from LEPCHA PUNCTUATION TA-ROL
	while (c <= 0x1c49)	// ..to LEPCHA DIGIT NINE
		charset[i++] = c++;
	charset[i++] = 0x1c4d;	// LEPCHA LETTER TTA
	charset[i++] = 0x1c4f;	// LEPCHA LETTER DDA
// 1C50..1C7F; Ol Chiki
	c = 0x1c50;		// from OL CHIKI DIGIT ZERO
	while (c <= 0x1c7f)	// ..to OL CHIKI PUNCTUATION DOUBLE MUCAAD
		charset[i++] = c++;
// 1C80..1C8F; Cyrillic Extended-C
	c = 0x1c80;		// from CYRILLIC SMALL LETTER ROUNDED VE
	while (c <= 0x1c88)	// ..to CYRILLIC SMALL LETTER UNBLENDED UK
		charset[i++] = c++;
// 1C90..1CBF; Georgian Extended
	c = 0x1c90;		// from GEORGIAN MTAVRULI CAPITAL LETTER AN
	while (c <= 0x1cba)	// ..to GEORGIAN MTAVRULI CAPITAL LETTER AIN
		charset[i++] = c++;
	charset[i++] = 0x1cbd;	// GEORGIAN MTAVRULI CAPITAL LETTER AEN
	charset[i++] = 0x1cbf;	// GEORGIAN MTAVRULI CAPITAL LETTER LABIAL SIGN
// 1CC0..1CCF; Sundanese Supplement
	c = 0x1cc0;		// from SUNDANESE PUNCTUATION BINDU SURYA
	while (c <= 0x1cc7)	// ..to SUNDANESE PUNCTUATION BINDU BA SATANGA
		charset[i++] = c++;
// 1CD0..1CFF; Vedic Extensions
	c = 0x1cd0;		// from VEDIC TONE KARSHANA
	while (c <= 0x1cfa)	// ..to VEDIC SIGN DOUBLE ANUSVARA ANTARGOMUKHA
		charset[i++] = c++;
// 1D00..1D7F; Phonetic Extensions
	c = 0x1d00;		// from LATIN LETTER SMALL CAPITAL A
	while (c <= 0x1d7f)	// ..to LATIN SMALL LETTER UPSILON WITH STROKE
		charset[i++] = c++;
// 1D80..1DBF; Phonetic Extensions Supplement
	c = 0x1d80;		// from LATIN SMALL LETTER B WITH PALATAL HOOK
	while (c <= 0x1dbf)	// ..to MODIFIER LETTER SMALL THETA
		charset[i++] = c++;
// 1DC0..1DFF; Combining Diacritical Marks Supplement
	c = 0x1dc0;		// from COMBINING DOTTED GRAVE ACCENT
	while (c <= 0x1df9)	// ..to COMBINING WIDE INVERTED BRIDGE BELOW
		charset[i++] = c++;
	c = 0x1dfb;		// from COMBINING DELETION MARK
	while (c <= 0x1dff)	// ..to COMBINING RIGHT ARROWHEAD AND DOWN ARROWHEAD BELOW
		charset[i++] = c++;
// 1E00..1EFF; Latin Extended Additional
	c = 0x1e00;		// from LATIN CAPITAL LETTER A WITH RING BELOW
	while (c <= 0x1eff)	// ..to LATIN SMALL LETTER Y WITH LOOP
		charset[i++] = c++;
// 1F00..1FFF; Greek Extended
	c = 0x1f00;		// from GREEK SMALL LETTER ALPHA WITH PSILI
	while (c <= 0x1f15)	// ..to GREEK SMALL LETTER EPSILON WITH DASIA AND OXIA
		charset[i++] = c++;
	c = 0x1f18;		// from GREEK CAPITAL LETTER EPSILON WITH PSILI
	while (c <= 0x1f1d)	// ..to GREEK CAPITAL LETTER EPSILON WITH DASIA AND OXIA
		charset[i++] = c++;
	c = 0x1f20;		// from GREEK SMALL LETTER ETA WITH PSILI
	while (c <= 0x1f45)	// ..to GREEK SMALL LETTER OMICRON WITH DASIA AND OXIA
		charset[i++] = c++;
	c = 0x1f48;		// from GREEK CAPITAL LETTER OMICRON WITH PSILI
	while (c <= 0x1f4d)	// ..to GREEK CAPITAL LETTER OMICRON WITH DASIA AND OXIA
		charset[i++] = c++;
	c = 0x1f50;		// from GREEK SMALL LETTER UPSILON WITH PSILI
	while (c <= 0x1f57)	// ..to GREEK SMALL LETTER UPSILON WITH DASIA AND PERISPOMENI
		charset[i++] = c++;
	c = 0x1f5f;		// from GREEK CAPITAL LETTER UPSILON WITH DASIA AND PERISPOMENI
	while (c <= 0x1f7d)	// ..to GREEK SMALL LETTER OMEGA WITH OXIA
		charset[i++] = c++;
	c = 0x1f80;		// from GREEK SMALL LETTER ALPHA WITH PSILI AND YPOGEGRAMMENI
	while (c <= 0x1fb4)	// ..to GREEK SMALL LETTER ALPHA WITH OXIA AND YPOGEGRAMMENI
		charset[i++] = c++;
	c = 0x1fb6;		// from GREEK SMALL LETTER ALPHA WITH PERISPOMENI
	while (c <= 0x1fc4)	// ..to GREEK SMALL LETTER ETA WITH OXIA AND YPOGEGRAMMENI
		charset[i++] = c++;
	c = 0x1fc6;		// from GREEK SMALL LETTER ETA WITH PERISPOMENI
	while (c <= 0x1fd3)	// ..to GREEK SMALL LETTER IOTA WITH DIALYTIKA AND OXIA
		charset[i++] = c++;
	c = 0x1fd6;		// from GREEK SMALL LETTER IOTA WITH PERISPOMENI
	while (c <= 0x1fdb)	// ..to GREEK CAPITAL LETTER IOTA WITH OXIA
		charset[i++] = c++;
	c = 0x1fdd;		// from GREEK DASIA AND VARIA
	while (c <= 0x1fef)	// ..to GREEK VARIA
		charset[i++] = c++;
	charset[i++] = 0x1ff2;	// GREEK SMALL LETTER OMEGA WITH VARIA AND YPOGEGRAMMENI
	charset[i++] = 0x1ff4;	// GREEK SMALL LETTER OMEGA WITH OXIA AND YPOGEGRAMMENI
	c = 0x1ff6;		// from GREEK SMALL LETTER OMEGA WITH PERISPOMENI
	while (c <= 0x1ffe)	// ..to GREEK DASIA
		charset[i++] = c++;
// 2000..206F; General Punctuation
	c = 0x2000;		// from EN QUAD
	while (c <= 0x2064)	// ..to INVISIBLE PLUS
		charset[i++] = c++;
	c = 0x2066;		// from LEFT-TO-RIGHT ISOLATE
	while (c <= 0x206f)	// ..to NOMINAL DIGIT SHAPES
		charset[i++] = c++;
// 2070..209F; Superscripts and Subscripts
	charset[i++] = 0x2070;	// SUPERSCRIPT ZERO
	charset[i++] = 0x2071;	// SUPERSCRIPT LATIN SMALL LETTER I
	c = 0x2074;		// from SUPERSCRIPT FOUR
	while (c <= 0x208e)	// ..to SUBSCRIPT RIGHT PARENTHESIS
		charset[i++] = c++;
	c = 0x2090;		// from LATIN SUBSCRIPT SMALL LETTER A
	while (c <= 0x209c)	// ..to LATIN SUBSCRIPT SMALL LETTER T
		charset[i++] = c++;
// 20A0..20CF; Currency Symbols
	c = 0x20a0;		// from EURO-CURRENCY SIGN
	while (c <= 0x20bf)	// ..to BITCOIN SIGN
		charset[i++] = c++;
// 20D0..20FF; Combining Diacritical Marks for Symbols
	c = 0x20d0;		// from COMBINING LEFT HARPOON ABOVE
	while (c <= 0x20f0)	// ..to COMBINING ASTERISK ABOVE
		charset[i++] = c++;
// 2100..214F; Letterlike Symbols
	c = 0x2100;		// from ACCOUNT OF
	while (c <= 0x214f)	// ..to SYMBOL FOR SAMARITAN SOURCE
		charset[i++] = c++;
// 2150..218F; Number Forms
	c = 0x2150;		// from VULGAR FRACTION ONE SEVENTH
	while (c <= 0x218b)	// ..to TURNED DIGIT THREE
		charset[i++] = c++;
// 2190..21FF; Arrows
	c = 0x2190;		// from LEFTWARDS ARROW
	while (c <= 0x21ff)	// ..to LEFT RIGHT OPEN-HEADED ARROW
		charset[i++] = c++;
// 2200..22FF; Mathematical Operators
	c = 0x2200;		// from FOR ALL
	while (c <= 0x22ff)	// ..to Z NOTATION BAG MEMBERSHIP
		charset[i++] = c++;
// 2300..23FF; Miscellaneous Technical
	c = 0x2300;		// from DIAMETER SIGN
	while (c <= 0x23ff)	// ..to OBSERVER EYE SYMBOL
		charset[i++] = c++;
// 2400..243F; Control Pictures
	c = 0x2400;		// from SYMBOL FOR NULL
	while (c <= 0x2426)	// ..to SYMBOL FOR SUBSTITUTE FORM TWO
		charset[i++] = c++;
// 2440..245F; Optical Character Recognition
	c = 0x2440;		// from OCR HOOK
	while (c <= 0x244a)	// ..to OCR DOUBLE BACKSLASH
		charset[i++] = c++;
// 2460..24FF; Enclosed Alphanumerics
	c = 0x2460;		// from CIRCLED DIGIT ONE
	while (c <= 0x24ff)	// ..to NEGATIVE CIRCLED DIGIT ZERO
		charset[i++] = c++;
// 2500..257F; Box Drawing
	c = 0x2500;		// from BOX DRAWINGS LIGHT HORIZONTAL
	while (c <= 0x257f)	// ..to BOX DRAWINGS HEAVY UP AND LIGHT DOWN
		charset[i++] = c++;
// 2580..259F; Block Elements
	c = 0x2580;		// from UPPER HALF BLOCK
	while (c <= 0x259f)	// ..to QUADRANT UPPER RIGHT AND LOWER LEFT AND LOWER RIGHT
		charset[i++] = c++;
// 25A0..25FF; Geometric Shapes
	c = 0x25a0;		// from BLACK SQUARE
	while (c <= 0x25ff)	// ..to LOWER RIGHT TRIANGLE
		charset[i++] = c++;
// 2600..26FF; Miscellaneous Symbols
	c = 0x2600;		// from BLACK SUN WITH RAYS
	while (c <= 0x26ff)	// ..to WHITE FLAG WITH HORIZONTAL MIDDLE BLACK STRIPE
		charset[i++] = c++;
// 2700..27BF; Dingbats
	c = 0x2700;		// from BLACK SAFETY SCISSORS
	while (c <= 0x27bf)	// ..to DOUBLE CURLY LOOP
		charset[i++] = c++;
// 27C0..27EF; Miscellaneous Mathematical Symbols-A
	c = 0x27c0;		// from THREE DIMENSIONAL ANGLE
	while (c <= 0x27ef)	// ..to MATHEMATICAL RIGHT FLATTENED PARENTHESIS
		charset[i++] = c++;
// 27F0..27FF; Supplemental Arrows-A
	c = 0x27f0;		// from UPWARDS QUADRUPLE ARROW
	while (c <= 0x27ff)	// ..to LONG RIGHTWARDS SQUIGGLE ARROW
		charset[i++] = c++;
// 2800..28FF; Braille Patterns
	c = 0x2800;		// from BRAILLE PATTERN BLANK
	while (c <= 0x28ff)	// ..to BRAILLE PATTERN DOTS-12345678
		charset[i++] = c++;
// 2900..297F; Supplemental Arrows-B
	c = 0x2900;		// from RIGHTWARDS TWO-HEADED ARROW WITH VERTICAL STROKE
	while (c <= 0x297f)	// ..to DOWN FISH TAIL
		charset[i++] = c++;
// 2980..29FF; Miscellaneous Mathematical Symbols-B
	c = 0x2980;		// from TRIPLE VERTICAL BAR DELIMITER
	while (c <= 0x29ff)	// ..to MINY
		charset[i++] = c++;
// 2A00..2AFF; Supplemental Mathematical Operators
	c = 0x2a00;		// from N-ARY CIRCLED DOT OPERATOR
	while (c <= 0x2aff)	// ..to N-ARY WHITE VERTICAL BAR
		charset[i++] = c++;
// 2B00..2BFF; Miscellaneous Symbols and Arrows
	c = 0x2b00;		// from NORTH EAST WHITE ARROW
	while (c <= 0x2b73)	// ..to DOWNWARDS TRIANGLE-HEADED ARROW TO BAR
		charset[i++] = c++;
	c = 0x2b76;		// from NORTH WEST TRIANGLE-HEADED ARROW TO BAR
	while (c <= 0x2b95)	// ..to RIGHTWARDS BLACK ARROW
		charset[i++] = c++;
	c = 0x2b97;		// from SYMBOL FOR TYPE A ELECTRONICS
	while (c <= 0x2bff)	// ..to HELLSCHREIBER PAUSE SYMBOL
		charset[i++] = c++;
// 2C00..2C5F; Glagolitic
	c = 0x2c00;		// from GLAGOLITIC CAPITAL LETTER AZU
	while (c <= 0x2c2e)	// ..to GLAGOLITIC CAPITAL LETTER LATINATE MYSLITE
		charset[i++] = c++;
	c = 0x2c30;		// from GLAGOLITIC SMALL LETTER AZU
	while (c <= 0x2c5e)	// ..to GLAGOLITIC SMALL LETTER LATINATE MYSLITE
		charset[i++] = c++;
// 2C60..2C7F; Latin Extended-C
	c = 0x2c60;		// from LATIN CAPITAL LETTER L WITH DOUBLE BAR
	while (c <= 0x2c7f)	// ..to LATIN CAPITAL LETTER Z WITH SWASH TAIL
		charset[i++] = c++;
// 2C80..2CFF; Coptic
	c = 0x2c80;		// from COPTIC CAPITAL LETTER ALFA
	while (c <= 0x2cf3)	// ..to COPTIC SMALL LETTER BOHAIRIC KHEI
		charset[i++] = c++;
	c = 0x2cf9;		// from COPTIC OLD NUBIAN FULL STOP
	while (c <= 0x2cff)	// ..to COPTIC MORPHOLOGICAL DIVIDER
		charset[i++] = c++;
// 2D00..2D2F; Georgian Supplement
	c = 0x2d00;		// from GEORGIAN SMALL LETTER AN
	while (c <= 0x2d25)	// ..to GEORGIAN SMALL LETTER HOE
		charset[i++] = c++;
	c = 0x2d27;		// from GEORGIAN SMALL LETTER YN
	while (c <= 0x2d2d)	// ..to GEORGIAN SMALL LETTER AEN
		charset[i++] = c++;
// 2D30..2D7F; Tifinagh
	c = 0x2d30;		// from TIFINAGH LETTER YA
	while (c <= 0x2d67)	// ..to TIFINAGH LETTER YO
		charset[i++] = c++;
	charset[i++] = 0x2d6f;	// TIFINAGH MODIFIER LETTER LABIALIZATION MARK
	charset[i++] = 0x2d70;	// TIFINAGH SEPARATOR MARK
	charset[i++] = 0x2d7f;	// TIFINAGH CONSONANT JOINER
// 2D80..2DDF; Ethiopic Extended
	c = 0x2d80;		// from ETHIOPIC SYLLABLE LOA
	while (c <= 0x2d96)	// ..to ETHIOPIC SYLLABLE GGWE
		charset[i++] = c++;
	c = 0x2da0;		// from ETHIOPIC SYLLABLE SSA
	while (c <= 0x2da6)	// ..to ETHIOPIC SYLLABLE SSO
		charset[i++] = c++;
	c = 0x2da8;		// from ETHIOPIC SYLLABLE CCA
	while (c <= 0x2dae)	// ..to ETHIOPIC SYLLABLE CCO
		charset[i++] = c++;
	c = 0x2db0;		// from ETHIOPIC SYLLABLE ZZA
	while (c <= 0x2db6)	// ..to ETHIOPIC SYLLABLE ZZO
		charset[i++] = c++;
	c = 0x2db8;		// from ETHIOPIC SYLLABLE CCHA
	while (c <= 0x2dbe)	// ..to ETHIOPIC SYLLABLE CCHO
		charset[i++] = c++;
	c = 0x2dc0;		// from ETHIOPIC SYLLABLE QYA
	while (c <= 0x2dc6)	// ..to ETHIOPIC SYLLABLE QYO
		charset[i++] = c++;
	c = 0x2dc8;		// from ETHIOPIC SYLLABLE KYA
	while (c <= 0x2dce)	// ..to ETHIOPIC SYLLABLE KYO
		charset[i++] = c++;
	c = 0x2dd0;		// from ETHIOPIC SYLLABLE XYA
	while (c <= 0x2dd6)	// ..to ETHIOPIC SYLLABLE XYO
		charset[i++] = c++;
	c = 0x2dd8;		// from ETHIOPIC SYLLABLE GYA
	while (c <= 0x2dde)	// ..to ETHIOPIC SYLLABLE GYO
		charset[i++] = c++;
// 2DE0..2DFF; Cyrillic Extended-A
	c = 0x2de0;		// from COMBINING CYRILLIC LETTER BE
	while (c <= 0x2dff)	// ..to COMBINING CYRILLIC LETTER IOTIFIED BIG YUS
		charset[i++] = c++;
// 2E00..2E7F; Supplemental Punctuation
	c = 0x2e00;		// from RIGHT ANGLE SUBSTITUTION MARKER
	while (c <= 0x2e52)	// ..to TIRONIAN SIGN CAPITAL ET
		charset[i++] = c++;
// 2E80..2EFF; CJK Radicals Supplement
	c = 0x2e80;		// from CJK RADICAL REPEAT
	while (c <= 0x2e99)	// ..to CJK RADICAL RAP
		charset[i++] = c++;
	c = 0x2e9b;		// from CJK RADICAL CHOKE
	while (c <= 0x2ef3)	// ..to CJK RADICAL C-SIMPLIFIED TURTLE
		charset[i++] = c++;
// 2F00..2FDF; Kangxi Radicals
	c = 0x2f00;		// from KANGXI RADICAL ONE
	while (c <= 0x2fd5)	// ..to KANGXI RADICAL FLUTE
		charset[i++] = c++;
// 2FF0..2FFF; Ideographic Description Characters
	c = 0x2ff0;		// from IDEOGRAPHIC DESCRIPTION CHARACTER LEFT TO RIGHT
	while (c <= 0x2ffb)	// ..to IDEOGRAPHIC DESCRIPTION CHARACTER OVERLAID
		charset[i++] = c++;
// 3000..303F; CJK Symbols and Punctuation
	c = 0x3000;		// from IDEOGRAPHIC SPACE
	while (c <= 0x303f)	// ..to IDEOGRAPHIC HALF FILL SPACE
		charset[i++] = c++;
// 3040..309F; Hiragana
	c = 0x3041;		// from HIRAGANA LETTER SMALL A
	while (c <= 0x3096)	// ..to HIRAGANA LETTER SMALL KE
		charset[i++] = c++;
	c = 0x3099;		// from COMBINING KATAKANA-HIRAGANA VOICED SOUND MARK
	while (c <= 0x309f)	// ..to HIRAGANA DIGRAPH YORI
		charset[i++] = c++;
// 30A0..30FF; Katakana
	c = 0x30a0;		// from KATAKANA-HIRAGANA DOUBLE HYPHEN
	while (c <= 0x30ff)	// ..to KATAKANA DIGRAPH KOTO
		charset[i++] = c++;
// 3100..312F; Bopomofo
	c = 0x3105;		// from BOPOMOFO LETTER B
	while (c <= 0x312f)	// ..to BOPOMOFO LETTER NN
		charset[i++] = c++;
// 3130..318F; Hangul Compatibility Jamo
	c = 0x3131;		// from HANGUL LETTER KIYEOK
	while (c <= 0x318e)	// ..to HANGUL LETTER ARAEAE
		charset[i++] = c++;
// 3190..319F; Kanbun
	c = 0x3190;		// from IDEOGRAPHIC ANNOTATION LINKING MARK
	while (c <= 0x319f)	// ..to IDEOGRAPHIC ANNOTATION MAN MARK
		charset[i++] = c++;
// 31A0..31BF; Bopomofo Extended
	c = 0x31a0;		// from BOPOMOFO LETTER BU
	while (c <= 0x31bf)	// ..to BOPOMOFO LETTER AH
		charset[i++] = c++;
// 31C0..31EF; CJK Strokes
	c = 0x31c0;		// from CJK STROKE T
	while (c <= 0x31e3)	// ..to CJK STROKE Q
		charset[i++] = c++;
// 31F0..31FF; Katakana Phonetic Extensions
	c = 0x31f0;		// from KATAKANA LETTER SMALL KU
	while (c <= 0x31ff)	// ..to KATAKANA LETTER SMALL RO
		charset[i++] = c++;
// 3200..32FF; Enclosed CJK Letters and Months
	c = 0x3200;		// from PARENTHESIZED HANGUL KIYEOK
	while (c <= 0x321e)	// ..to PARENTHESIZED KOREAN CHARACTER O HU
		charset[i++] = c++;
	c = 0x3220;		// from PARENTHESIZED IDEOGRAPH ONE
	while (c <= 0x32ff)	// ..to SQUARE ERA NAME REIWA
		charset[i++] = c++;
// 3300..33FF; CJK Compatibility
	c = 0x3300;		// from SQUARE APAATO
	while (c <= 0x33ff)	// ..to SQUARE GAL
		charset[i++] = c++;
// 3400..4DBF; CJK Unified Ideographs Extension A
	c = 0x3400;		// from <CJK Ideograph Extension A, First>
	while (c <= 0x4dbf)	// ..to <CJK Ideograph Extension A, Last>
		charset[i++] = c++;
// 4DC0..4DFF; Yijing Hexagram Symbols
	c = 0x4dc0;		// from HEXAGRAM FOR THE CREATIVE HEAVEN
	while (c <= 0x4dff)	// ..to HEXAGRAM FOR BEFORE COMPLETION
		charset[i++] = c++;
// 4E00..9FFF; CJK Unified Ideographs
	c = 0x4e00;		// from <CJK Ideograph, First>
	while (c <= 0x9ffc)	// ..to <CJK Ideograph, Last>
		charset[i++] = c++;
// A000..A48F; Yi Syllables
	c = 0xa000;		// from YI SYLLABLE IT
	while (c <= 0xa48c)	// ..to YI SYLLABLE YYR
		charset[i++] = c++;
// A490..A4CF; Yi Radicals
	c = 0xa490;		// from YI RADICAL QOT
	while (c <= 0xa4c6)	// ..to YI RADICAL KE
		charset[i++] = c++;
// A4D0..A4FF; Lisu
	c = 0xa4d0;		// from LISU LETTER BA
	while (c <= 0xa4ff)	// ..to LISU PUNCTUATION FULL STOP
		charset[i++] = c++;
// A500..A63F; Vai
	c = 0xa500;		// from VAI SYLLABLE EE
	while (c <= 0xa62b)	// ..to VAI SYLLABLE NDOLE DO
		charset[i++] = c++;
// A640..A69F; Cyrillic Extended-B
	c = 0xa640;		// from CYRILLIC CAPITAL LETTER ZEMLYA
	while (c <= 0xa69f)	// ..to COMBINING CYRILLIC LETTER IOTIFIED E
		charset[i++] = c++;
// A6A0..A6FF; Bamum
	c = 0xa6a0;		// from BAMUM LETTER A
	while (c <= 0xa6f7)	// ..to BAMUM QUESTION MARK
		charset[i++] = c++;
// A700..A71F; Modifier Tone Letters
	c = 0xa700;		// from MODIFIER LETTER CHINESE TONE YIN PING
	while (c <= 0xa71f)	// ..to MODIFIER LETTER LOW INVERTED EXCLAMATION MARK
		charset[i++] = c++;
// A720..A7FF; Latin Extended-D
	c = 0xa720;		// from MODIFIER LETTER STRESS AND HIGH TONE
	while (c <= 0xa7bf)	// ..to LATIN SMALL LETTER GLOTTAL U
		charset[i++] = c++;
	c = 0xa7c2;		// from LATIN CAPITAL LETTER ANGLICANA W
	while (c <= 0xa7ca)	// ..to LATIN SMALL LETTER S WITH SHORT STROKE OVERLAY
		charset[i++] = c++;
	c = 0xa7f5;		// from LATIN CAPITAL LETTER REVERSED HALF H
	while (c <= 0xa7ff)	// ..to LATIN EPIGRAPHIC LETTER ARCHAIC M
		charset[i++] = c++;
// A800..A82F; Syloti Nagri
	c = 0xa800;		// from SYLOTI NAGRI LETTER A
	while (c <= 0xa82c)	// ..to SYLOTI NAGRI SIGN ALTERNATE HASANTA
		charset[i++] = c++;
// A830..A83F; Common Indic Number Forms
	c = 0xa830;		// from NORTH INDIC FRACTION ONE QUARTER
	while (c <= 0xa839)	// ..to NORTH INDIC QUANTITY MARK
		charset[i++] = c++;
// A840..A87F; Phags-pa
	c = 0xa840;		// from PHAGS-PA LETTER KA
	while (c <= 0xa877)	// ..to PHAGS-PA MARK DOUBLE SHAD
		charset[i++] = c++;
// A880..A8DF; Saurashtra
	c = 0xa880;		// from SAURASHTRA SIGN ANUSVARA
	while (c <= 0xa8c5)	// ..to SAURASHTRA SIGN CANDRABINDU
		charset[i++] = c++;
	c = 0xa8ce;		// from SAURASHTRA DANDA
	while (c <= 0xa8d9)	// ..to SAURASHTRA DIGIT NINE
		charset[i++] = c++;
// A8E0..A8FF; Devanagari Extended
	c = 0xa8e0;		// from COMBINING DEVANAGARI DIGIT ZERO
	while (c <= 0xa8ff)	// ..to DEVANAGARI VOWEL SIGN AY
		charset[i++] = c++;
// A900..A92F; Kayah Li
	c = 0xa900;		// from KAYAH LI DIGIT ZERO
	while (c <= 0xa92f)	// ..to KAYAH LI SIGN SHYA
		charset[i++] = c++;
// A930..A95F; Rejang
	c = 0xa930;		// from REJANG LETTER KA
	while (c <= 0xa953)	// ..to REJANG VIRAMA
		charset[i++] = c++;
	charset[i++] = 0xa95f;	// REJANG SECTION MARK
// A960..A97F; Hangul Jamo Extended-A
	c = 0xa960;		// from HANGUL CHOSEONG TIKEUT-MIEUM
	while (c <= 0xa97c)	// ..to HANGUL CHOSEONG SSANGYEORINHIEUH
		charset[i++] = c++;
// A980..A9DF; Javanese
	c = 0xa980;		// from JAVANESE SIGN PANYANGGA
	while (c <= 0xa9cd)	// ..to JAVANESE TURNED PADA PISELEH
		charset[i++] = c++;
	c = 0xa9cf;		// from JAVANESE PANGRANGKEP
	while (c <= 0xa9d9)	// ..to JAVANESE DIGIT NINE
		charset[i++] = c++;
	charset[i++] = 0xa9de;	// JAVANESE PADA TIRTA TUMETES
	charset[i++] = 0xa9df;	// JAVANESE PADA ISEN-ISEN
// A9E0..A9FF; Myanmar Extended-B
	c = 0xa9e0;		// from MYANMAR LETTER SHAN GHA
	while (c <= 0xa9fe)	// ..to MYANMAR LETTER TAI LAING BHA
		charset[i++] = c++;
// AA00..AA5F; Cham
	c = 0xaa00;		// from CHAM LETTER A
	while (c <= 0xaa36)	// ..to CHAM CONSONANT SIGN WA
		charset[i++] = c++;
	c = 0xaa40;		// from CHAM LETTER FINAL K
	while (c <= 0xaa4d)	// ..to CHAM CONSONANT SIGN FINAL H
		charset[i++] = c++;
	c = 0xaa50;		// from CHAM DIGIT ZERO
	while (c <= 0xaa59)	// ..to CHAM DIGIT NINE
		charset[i++] = c++;
	c = 0xaa5c;		// from CHAM PUNCTUATION SPIRAL
	while (c <= 0xaa5f)	// ..to CHAM PUNCTUATION TRIPLE DANDA
		charset[i++] = c++;
// AA60..AA7F; Myanmar Extended-A
	c = 0xaa60;		// from MYANMAR LETTER KHAMTI GA
	while (c <= 0xaa7f)	// ..to MYANMAR LETTER SHWE PALAUNG SHA
		charset[i++] = c++;
// AA80..AADF; Tai Viet
	c = 0xaa80;		// from TAI VIET LETTER LOW KO
	while (c <= 0xaac2)	// ..to TAI VIET TONE MAI SONG
		charset[i++] = c++;
	c = 0xaadb;		// from TAI VIET SYMBOL KON
	while (c <= 0xaadf)	// ..to TAI VIET SYMBOL KOI KOI
		charset[i++] = c++;
// AAE0..AAFF; Meetei Mayek Extensions
	c = 0xaae0;		// from MEETEI MAYEK LETTER E
	while (c <= 0xaaf6)	// ..to MEETEI MAYEK VIRAMA
		charset[i++] = c++;
// AB00..AB2F; Ethiopic Extended-A
	c = 0xab01;		// from ETHIOPIC SYLLABLE TTHU
	while (c <= 0xab06)	// ..to ETHIOPIC SYLLABLE TTHO
		charset[i++] = c++;
	c = 0xab09;		// from ETHIOPIC SYLLABLE DDHU
	while (c <= 0xab0e)	// ..to ETHIOPIC SYLLABLE DDHO
		charset[i++] = c++;
	c = 0xab11;		// from ETHIOPIC SYLLABLE DZU
	while (c <= 0xab16)	// ..to ETHIOPIC SYLLABLE DZO
		charset[i++] = c++;
	c = 0xab20;		// from ETHIOPIC SYLLABLE CCHHA
	while (c <= 0xab26)	// ..to ETHIOPIC SYLLABLE CCHHO
		charset[i++] = c++;
	c = 0xab28;		// from ETHIOPIC SYLLABLE BBA
	while (c <= 0xab2e)	// ..to ETHIOPIC SYLLABLE BBO
		charset[i++] = c++;
// AB30..AB6F; Latin Extended-E
	c = 0xab30;		// from LATIN SMALL LETTER BARRED ALPHA
	while (c <= 0xab6b)	// ..to MODIFIER LETTER RIGHT TACK
		charset[i++] = c++;
// AB70..ABBF; Cherokee Supplement
	c = 0xab70;		// from CHEROKEE SMALL LETTER A
	while (c <= 0xabbf)	// ..to CHEROKEE SMALL LETTER YA
		charset[i++] = c++;
// ABC0..ABFF; Meetei Mayek
	c = 0xabc0;		// from MEETEI MAYEK LETTER KOK
	while (c <= 0xabed)	// ..to MEETEI MAYEK APUN IYEK
		charset[i++] = c++;
	c = 0xabf0;		// from MEETEI MAYEK DIGIT ZERO
	while (c <= 0xabf9)	// ..to MEETEI MAYEK DIGIT NINE
		charset[i++] = c++;
// AC00..D7AF; Hangul Syllables
	c = 0xac00;		// from <Hangul Syllable, First>
	while (c <= 0xd7a3)	// ..to <Hangul Syllable, Last>
		charset[i++] = c++;
// D7B0..D7FF; Hangul Jamo Extended-B
	c = 0xd7b0;		// from HANGUL JUNGSEONG O-YEO
	while (c <= 0xd7c6)	// ..to HANGUL JUNGSEONG ARAEA-E
		charset[i++] = c++;
	c = 0xd7cb;		// from HANGUL JONGSEONG NIEUN-RIEUL
	while (c <= 0xd7fb)	// ..to HANGUL JONGSEONG PHIEUPH-THIEUTH
		charset[i++] = c++;
// D800..DB7F; High Surrogates
// DB80..DBFF; High Private Use Surrogates
// DC00..DFFF; Low Surrogates
// E000..F8FF; Private Use Area
// F900..FAFF; CJK Compatibility Ideographs
	c = 0xf900;		// from CJK COMPATIBILITY IDEOGRAPH-F900
	while (c <= 0xfa6d)	// ..to CJK COMPATIBILITY IDEOGRAPH-FA6D
		charset[i++] = c++;
	c = 0xfa70;		// from CJK COMPATIBILITY IDEOGRAPH-FA70
	while (c <= 0xfad9)	// ..to CJK COMPATIBILITY IDEOGRAPH-FAD9
		charset[i++] = c++;
// FB00..FB4F; Alphabetic Presentation Forms
	c = 0xfb00;		// from LATIN SMALL LIGATURE FF
	while (c <= 0xfb06)	// ..to LATIN SMALL LIGATURE ST
		charset[i++] = c++;
	c = 0xfb13;		// from ARMENIAN SMALL LIGATURE MEN NOW
	while (c <= 0xfb17)	// ..to ARMENIAN SMALL LIGATURE MEN XEH
		charset[i++] = c++;
	c = 0xfb1d;		// from HEBREW LETTER YOD WITH HIRIQ
	while (c <= 0xfb36)	// ..to HEBREW LETTER ZAYIN WITH DAGESH
		charset[i++] = c++;
	c = 0xfb38;		// from HEBREW LETTER TET WITH DAGESH
	while (c <= 0xfb3c)	// ..to HEBREW LETTER LAMED WITH DAGESH
		charset[i++] = c++;
	charset[i++] = 0xfb40;	// HEBREW LETTER NUN WITH DAGESH
	charset[i++] = 0xfb41;	// HEBREW LETTER SAMEKH WITH DAGESH
	charset[i++] = 0xfb43;	// HEBREW LETTER FINAL PE WITH DAGESH
	charset[i++] = 0xfb44;	// HEBREW LETTER PE WITH DAGESH
	c = 0xfb46;		// from HEBREW LETTER TSADI WITH DAGESH
	while (c <= 0xfb4f)	// ..to HEBREW LIGATURE ALEF LAMED
		charset[i++] = c++;
// FB50..FDFF; Arabic Presentation Forms-A
	c = 0xfb50;		// from ARABIC LETTER ALEF WASLA ISOLATED FORM
	while (c <= 0xfbc1)	// ..to ARABIC SYMBOL SMALL TAH BELOW
		charset[i++] = c++;
	c = 0xfbd3;		// from ARABIC LETTER NG ISOLATED FORM
	while (c <= 0xfd3f)	// ..to ORNATE RIGHT PARENTHESIS
		charset[i++] = c++;
	c = 0xfd50;		// from ARABIC LIGATURE TEH WITH JEEM WITH MEEM INITIAL FORM
	while (c <= 0xfd8f)	// ..to ARABIC LIGATURE MEEM WITH KHAH WITH MEEM INITIAL FORM
		charset[i++] = c++;
	c = 0xfd92;		// from ARABIC LIGATURE MEEM WITH JEEM WITH KHAH INITIAL FORM
	while (c <= 0xfdc7)	// ..to ARABIC LIGATURE NOON WITH JEEM WITH YEH FINAL FORM
		charset[i++] = c++;
	c = 0xfdf0;		// from ARABIC LIGATURE SALLA USED AS KORANIC STOP SIGN ISOLATED FORM
	while (c <= 0xfdfd)	// ..to ARABIC LIGATURE BISMILLAH AR-RAHMAN AR-RAHEEM
		charset[i++] = c++;
// FE00..FE0F; Variation Selectors
	c = 0xfe00;		// from VARIATION SELECTOR-1
	while (c <= 0xfe0f)	// ..to VARIATION SELECTOR-16
		charset[i++] = c++;
// FE10..FE1F; Vertical Forms
	c = 0xfe10;		// from PRESENTATION FORM FOR VERTICAL COMMA
	while (c <= 0xfe19)	// ..to PRESENTATION FORM FOR VERTICAL HORIZONTAL ELLIPSIS
		charset[i++] = c++;
// FE20..FE2F; Combining Half Marks
	c = 0xfe20;		// from COMBINING LIGATURE LEFT HALF
	while (c <= 0xfe2f)	// ..to COMBINING CYRILLIC TITLO RIGHT HALF
		charset[i++] = c++;
// FE30..FE4F; CJK Compatibility Forms
	c = 0xfe30;		// from PRESENTATION FORM FOR VERTICAL TWO DOT LEADER
	while (c <= 0xfe4f)	// ..to WAVY LOW LINE
		charset[i++] = c++;
// FE50..FE6F; Small Form Variants
	charset[i++] = 0xfe50;	// SMALL COMMA
	charset[i++] = 0xfe52;	// SMALL FULL STOP
	c = 0xfe54;		// from SMALL SEMICOLON
	while (c <= 0xfe66)	// ..to SMALL EQUALS SIGN
		charset[i++] = c++;
	c = 0xfe68;		// from SMALL REVERSE SOLIDUS
	while (c <= 0xfe6b)	// ..to SMALL COMMERCIAL AT
		charset[i++] = c++;
// FE70..FEFF; Arabic Presentation Forms-B
	c = 0xfe70;		// from ARABIC FATHATAN ISOLATED FORM
	while (c <= 0xfe74)	// ..to ARABIC KASRATAN ISOLATED FORM
		charset[i++] = c++;
	c = 0xfe76;		// from ARABIC FATHA ISOLATED FORM
	while (c <= 0xfefc)	// ..to ARABIC LIGATURE LAM WITH ALEF FINAL FORM
		charset[i++] = c++;
	charset[i++] = 0xfeff;	// ZERO WIDTH NO-BREAK SPACE
// FF00..FFEF; Halfwidth and Fullwidth Forms
	c = 0xff01;		// from FULLWIDTH EXCLAMATION MARK
	while (c <= 0xffbe)	// ..to HALFWIDTH HANGUL LETTER HIEUH
		charset[i++] = c++;
	c = 0xffc2;		// from HALFWIDTH HANGUL LETTER A
	while (c <= 0xffc7)	// ..to HALFWIDTH HANGUL LETTER E
		charset[i++] = c++;
	c = 0xffca;		// from HALFWIDTH HANGUL LETTER YEO
	while (c <= 0xffcf)	// ..to HALFWIDTH HANGUL LETTER OE
		charset[i++] = c++;
	c = 0xffd2;		// from HALFWIDTH HANGUL LETTER YO
	while (c <= 0xffd7)	// ..to HALFWIDTH HANGUL LETTER YU
		charset[i++] = c++;
	charset[i++] = 0xffda;	// HALFWIDTH HANGUL LETTER EU
	charset[i++] = 0xffdc;	// HALFWIDTH HANGUL LETTER I
	c = 0xffe0;		// from FULLWIDTH CENT SIGN
	while (c <= 0xffe6)	// ..to FULLWIDTH WON SIGN
		charset[i++] = c++;
	c = 0xffe8;		// from HALFWIDTH FORMS LIGHT VERTICAL
	while (c <= 0xffee)	// ..to HALFWIDTH WHITE CIRCLE
		charset[i++] = c++;
// FFF0..FFFF; Specials
	c = 0xfff9;		// from INTERLINEAR ANNOTATION ANCHOR
	while (c <= 0xfffd)	// ..to REPLACEMENT CHARACTER
		charset[i++] = c++;
// 10000..1007F; Linear B Syllabary
	c = 0x10000;		// from LINEAR B SYLLABLE B008 A
	while (c <= 0x1000b)	// ..to LINEAR B SYLLABLE B046 JE
		charset[i++] = c++;
	c = 0x1000d;		// from LINEAR B SYLLABLE B036 JO
	while (c <= 0x10026)	// ..to LINEAR B SYLLABLE B032 QO
		charset[i++] = c++;
	c = 0x10028;		// from LINEAR B SYLLABLE B060 RA
	while (c <= 0x1003a)	// ..to LINEAR B SYLLABLE B042 WO
		charset[i++] = c++;
	charset[i++] = 0x1003c;	// LINEAR B SYLLABLE B017 ZA
	charset[i++] = 0x1003d;	// LINEAR B SYLLABLE B074 ZE
	c = 0x1003f;		// from LINEAR B SYLLABLE B020 ZO
	while (c <= 0x1004d)	// ..to LINEAR B SYLLABLE B091 TWO
		charset[i++] = c++;
	c = 0x10050;		// from LINEAR B SYMBOL B018
	while (c <= 0x1005d)	// ..to LINEAR B SYMBOL B089
		charset[i++] = c++;
// 10080..100FF; Linear B Ideograms
	c = 0x10080;		// from LINEAR B IDEOGRAM B100 MAN
	while (c <= 0x100fa)	// ..to LINEAR B IDEOGRAM VESSEL B305
		charset[i++] = c++;
// 10100..1013F; Aegean Numbers
	charset[i++] = 0x10100;	// AEGEAN WORD SEPARATOR LINE
	charset[i++] = 0x10102;	// AEGEAN CHECK MARK
	c = 0x10107;		// from AEGEAN NUMBER ONE
	while (c <= 0x10133)	// ..to AEGEAN NUMBER NINETY THOUSAND
		charset[i++] = c++;
	c = 0x10137;		// from AEGEAN WEIGHT BASE UNIT
	while (c <= 0x1013f)	// ..to AEGEAN MEASURE THIRD SUBUNIT
		charset[i++] = c++;
// 10140..1018F; Ancient Greek Numbers
	c = 0x10140;		// from GREEK ACROPHONIC ATTIC ONE QUARTER
	while (c <= 0x1018e)	// ..to NOMISMA SIGN
		charset[i++] = c++;
// 10190..101CF; Ancient Symbols
	c = 0x10190;		// from ROMAN SEXTANS SIGN
	while (c <= 0x1019c)	// ..to ASCIA SYMBOL
		charset[i++] = c++;
	charset[i++] = 0x101a0;	// GREEK SYMBOL TAU RHO
// 101D0..101FF; Phaistos Disc
	c = 0x101d0;		// from PHAISTOS DISC SIGN PEDESTRIAN
	while (c <= 0x101fd)	// ..to PHAISTOS DISC SIGN COMBINING OBLIQUE STROKE
		charset[i++] = c++;
// 10280..1029F; Lycian
	c = 0x10280;		// from LYCIAN LETTER A
	while (c <= 0x1029c)	// ..to LYCIAN LETTER X
		charset[i++] = c++;
// 102A0..102DF; Carian
	c = 0x102a0;		// from CARIAN LETTER A
	while (c <= 0x102d0)	// ..to CARIAN LETTER UUU3
		charset[i++] = c++;
// 102E0..102FF; Coptic Epact Numbers
	c = 0x102e0;		// from COPTIC EPACT THOUSANDS MARK
	while (c <= 0x102fb)	// ..to COPTIC EPACT NUMBER NINE HUNDRED
		charset[i++] = c++;
// 10300..1032F; Old Italic
	c = 0x10300;		// from OLD ITALIC LETTER A
	while (c <= 0x10323)	// ..to OLD ITALIC NUMERAL FIFTY
		charset[i++] = c++;
	charset[i++] = 0x1032d;	// OLD ITALIC LETTER YE
	charset[i++] = 0x1032f;	// OLD ITALIC LETTER SOUTHERN TSE
// 10330..1034F; Gothic
	c = 0x10330;		// from GOTHIC LETTER AHSA
	while (c <= 0x1034a)	// ..to GOTHIC LETTER NINE HUNDRED
		charset[i++] = c++;
// 10350..1037F; Old Permic
	c = 0x10350;		// from OLD PERMIC LETTER AN
	while (c <= 0x1037a)	// ..to COMBINING OLD PERMIC LETTER SII
		charset[i++] = c++;
// 10380..1039F; Ugaritic
	c = 0x10380;		// from UGARITIC LETTER ALPA
	while (c <= 0x1039d)	// ..to UGARITIC LETTER SSU
		charset[i++] = c++;
	charset[i++] = 0x1039f;	// UGARITIC WORD DIVIDER
// 103A0..103DF; Old Persian
	c = 0x103a0;		// from OLD PERSIAN SIGN A
	while (c <= 0x103c3)	// ..to OLD PERSIAN SIGN HA
		charset[i++] = c++;
	c = 0x103c8;		// from OLD PERSIAN SIGN AURAMAZDAA
	while (c <= 0x103d5)	// ..to OLD PERSIAN NUMBER HUNDRED
		charset[i++] = c++;
// 10400..1044F; Deseret
	c = 0x10400;		// from DESERET CAPITAL LETTER LONG I
	while (c <= 0x1044f)	// ..to DESERET SMALL LETTER EW
		charset[i++] = c++;
// 10450..1047F; Shavian
	c = 0x10450;		// from SHAVIAN LETTER PEEP
	while (c <= 0x1047f)	// ..to SHAVIAN LETTER YEW
		charset[i++] = c++;
// 10480..104AF; Osmanya
	c = 0x10480;		// from OSMANYA LETTER ALEF
	while (c <= 0x1049d)	// ..to OSMANYA LETTER OO
		charset[i++] = c++;
	c = 0x104a0;		// from OSMANYA DIGIT ZERO
	while (c <= 0x104a9)	// ..to OSMANYA DIGIT NINE
		charset[i++] = c++;
// 104B0..104FF; Osage
	c = 0x104b0;		// from OSAGE CAPITAL LETTER A
	while (c <= 0x104d3)	// ..to OSAGE CAPITAL LETTER ZHA
		charset[i++] = c++;
	c = 0x104d8;		// from OSAGE SMALL LETTER A
	while (c <= 0x104fb)	// ..to OSAGE SMALL LETTER ZHA
		charset[i++] = c++;
// 10500..1052F; Elbasan
	c = 0x10500;		// from ELBASAN LETTER A
	while (c <= 0x10527)	// ..to ELBASAN LETTER KHE
		charset[i++] = c++;
// 10530..1056F; Caucasian Albanian
	c = 0x10530;		// from CAUCASIAN ALBANIAN LETTER ALT
	while (c <= 0x10563)	// ..to CAUCASIAN ALBANIAN LETTER KIW
		charset[i++] = c++;
	charset[i++] = 0x1056f;	// CAUCASIAN ALBANIAN CITATION MARK
// 10600..1077F; Linear A
	c = 0x10600;		// from LINEAR A SIGN AB001
	while (c <= 0x10736)	// ..to LINEAR A SIGN A664
		charset[i++] = c++;
	c = 0x10740;		// from LINEAR A SIGN A701 A
	while (c <= 0x10755)	// ..to LINEAR A SIGN A732 JE
		charset[i++] = c++;
	c = 0x10760;		// from LINEAR A SIGN A800
	while (c <= 0x10767)	// ..to LINEAR A SIGN A807
		charset[i++] = c++;
// 10800..1083F; Cypriot Syllabary
	c = 0x10800;		// from CYPRIOT SYLLABLE A
	while (c <= 0x10805)	// ..to CYPRIOT SYLLABLE JA
		charset[i++] = c++;
	c = 0x1080a;		// from CYPRIOT SYLLABLE KA
	while (c <= 0x10835)	// ..to CYPRIOT SYLLABLE WO
		charset[i++] = c++;
	charset[i++] = 0x10837;	// CYPRIOT SYLLABLE XA
	charset[i++] = 0x10838;	// CYPRIOT SYLLABLE XE
	c = 0x1083c;		// from CYPRIOT SYLLABLE ZA
	while (c <= 0x1083f)	// ..to CYPRIOT SYLLABLE ZO
		charset[i++] = c++;
// 10840..1085F; Imperial Aramaic
	c = 0x10840;		// from IMPERIAL ARAMAIC LETTER ALEPH
	while (c <= 0x10855)	// ..to IMPERIAL ARAMAIC LETTER TAW
		charset[i++] = c++;
	c = 0x10857;		// from IMPERIAL ARAMAIC SECTION SIGN
	while (c <= 0x1085f)	// ..to IMPERIAL ARAMAIC NUMBER TEN THOUSAND
		charset[i++] = c++;
// 10860..1087F; Palmyrene
	c = 0x10860;		// from PALMYRENE LETTER ALEPH
	while (c <= 0x1087f)	// ..to PALMYRENE NUMBER TWENTY
		charset[i++] = c++;
// 10880..108AF; Nabataean
	c = 0x10880;		// from NABATAEAN LETTER FINAL ALEPH
	while (c <= 0x1089e)	// ..to NABATAEAN LETTER TAW
		charset[i++] = c++;
	c = 0x108a7;		// from NABATAEAN NUMBER ONE
	while (c <= 0x108af)	// ..to NABATAEAN NUMBER ONE HUNDRED
		charset[i++] = c++;
// 108E0..108FF; Hatran
	c = 0x108e0;		// from HATRAN LETTER ALEPH
	while (c <= 0x108f2)	// ..to HATRAN LETTER QOPH
		charset[i++] = c++;
	charset[i++] = 0x108f4;	// HATRAN LETTER SHIN
	charset[i++] = 0x108f5;	// HATRAN LETTER TAW
	c = 0x108fb;		// from HATRAN NUMBER ONE
	while (c <= 0x108ff)	// ..to HATRAN NUMBER ONE HUNDRED
		charset[i++] = c++;
// 10900..1091F; Phoenician
	c = 0x10900;		// from PHOENICIAN LETTER ALF
	while (c <= 0x1091b)	// ..to PHOENICIAN NUMBER THREE
		charset[i++] = c++;
	charset[i++] = 0x1091f;	// PHOENICIAN WORD SEPARATOR
// 10920..1093F; Lydian
	c = 0x10920;		// from LYDIAN LETTER A
	while (c <= 0x10939)	// ..to LYDIAN LETTER C
		charset[i++] = c++;
	charset[i++] = 0x1093f;	// LYDIAN TRIANGULAR MARK
// 10980..1099F; Meroitic Hieroglyphs
	c = 0x10980;		// from MEROITIC HIEROGLYPHIC LETTER A
	while (c <= 0x1099f)	// ..to MEROITIC HIEROGLYPHIC SYMBOL VIDJ-2
		charset[i++] = c++;
// 109A0..109FF; Meroitic Cursive
	c = 0x109a0;		// from MEROITIC CURSIVE LETTER A
	while (c <= 0x109b7)	// ..to MEROITIC CURSIVE LETTER DA
		charset[i++] = c++;
	c = 0x109bc;		// from MEROITIC CURSIVE FRACTION ELEVEN TWELFTHS
	while (c <= 0x109cf)	// ..to MEROITIC CURSIVE NUMBER SEVENTY
		charset[i++] = c++;
	c = 0x109d2;		// from MEROITIC CURSIVE NUMBER ONE HUNDRED
	while (c <= 0x109ff)	// ..to MEROITIC CURSIVE FRACTION TEN TWELFTHS
		charset[i++] = c++;
// 10A00..10A5F; Kharoshthi
	c = 0x10a00;		// from KHAROSHTHI LETTER A
	while (c <= 0x10a03)	// ..to KHAROSHTHI VOWEL SIGN VOCALIC R
		charset[i++] = c++;
	charset[i++] = 0x10a05;	// KHAROSHTHI VOWEL SIGN E
	charset[i++] = 0x10a06;	// KHAROSHTHI VOWEL SIGN O
	c = 0x10a0c;		// from KHAROSHTHI VOWEL LENGTH MARK
	while (c <= 0x10a13)	// ..to KHAROSHTHI LETTER GHA
		charset[i++] = c++;
	charset[i++] = 0x10a15;	// KHAROSHTHI LETTER CA
	charset[i++] = 0x10a17;	// KHAROSHTHI LETTER JA
	c = 0x10a19;		// from KHAROSHTHI LETTER NYA
	while (c <= 0x10a35)	// ..to KHAROSHTHI LETTER VHA
		charset[i++] = c++;
	charset[i++] = 0x10a38;	// KHAROSHTHI SIGN BAR ABOVE
	charset[i++] = 0x10a3a;	// KHAROSHTHI SIGN DOT BELOW
	c = 0x10a3f;		// from KHAROSHTHI VIRAMA
	while (c <= 0x10a48)	// ..to KHAROSHTHI FRACTION ONE HALF
		charset[i++] = c++;
	c = 0x10a50;		// from KHAROSHTHI PUNCTUATION DOT
	while (c <= 0x10a58)	// ..to KHAROSHTHI PUNCTUATION LINES
		charset[i++] = c++;
// 10A60..10A7F; Old South Arabian
	c = 0x10a60;		// from OLD SOUTH ARABIAN LETTER HE
	while (c <= 0x10a7f)	// ..to OLD SOUTH ARABIAN NUMERIC INDICATOR
		charset[i++] = c++;
// 10A80..10A9F; Old North Arabian
	c = 0x10a80;		// from OLD NORTH ARABIAN LETTER HEH
	while (c <= 0x10a9f)	// ..to OLD NORTH ARABIAN NUMBER TWENTY
		charset[i++] = c++;
// 10AC0..10AFF; Manichaean
	c = 0x10ac0;		// from MANICHAEAN LETTER ALEPH
	while (c <= 0x10ae6)	// ..to MANICHAEAN ABBREVIATION MARK BELOW
		charset[i++] = c++;
	c = 0x10aeb;		// from MANICHAEAN NUMBER ONE
	while (c <= 0x10af6)	// ..to MANICHAEAN PUNCTUATION LINE FILLER
		charset[i++] = c++;
// 10B00..10B3F; Avestan
	c = 0x10b00;		// from AVESTAN LETTER A
	while (c <= 0x10b35)	// ..to AVESTAN LETTER HE
		charset[i++] = c++;
	c = 0x10b39;		// from AVESTAN ABBREVIATION MARK
	while (c <= 0x10b3f)	// ..to LARGE ONE RING OVER TWO RINGS PUNCTUATION
		charset[i++] = c++;
// 10B40..10B5F; Inscriptional Parthian
	c = 0x10b40;		// from INSCRIPTIONAL PARTHIAN LETTER ALEPH
	while (c <= 0x10b55)	// ..to INSCRIPTIONAL PARTHIAN LETTER TAW
		charset[i++] = c++;
	c = 0x10b58;		// from INSCRIPTIONAL PARTHIAN NUMBER ONE
	while (c <= 0x10b5f)	// ..to INSCRIPTIONAL PARTHIAN NUMBER ONE THOUSAND
		charset[i++] = c++;
// 10B60..10B7F; Inscriptional Pahlavi
	c = 0x10b60;		// from INSCRIPTIONAL PAHLAVI LETTER ALEPH
	while (c <= 0x10b72)	// ..to INSCRIPTIONAL PAHLAVI LETTER TAW
		charset[i++] = c++;
	c = 0x10b78;		// from INSCRIPTIONAL PAHLAVI NUMBER ONE
	while (c <= 0x10b7f)	// ..to INSCRIPTIONAL PAHLAVI NUMBER ONE THOUSAND
		charset[i++] = c++;
// 10B80..10BAF; Psalter Pahlavi
	c = 0x10b80;		// from PSALTER PAHLAVI LETTER ALEPH
	while (c <= 0x10b91)	// ..to PSALTER PAHLAVI LETTER TAW
		charset[i++] = c++;
	c = 0x10b99;		// from PSALTER PAHLAVI SECTION MARK
	while (c <= 0x10b9c)	// ..to PSALTER PAHLAVI FOUR DOTS WITH DOT
		charset[i++] = c++;
	c = 0x10ba9;		// from PSALTER PAHLAVI NUMBER ONE
	while (c <= 0x10baf)	// ..to PSALTER PAHLAVI NUMBER ONE HUNDRED
		charset[i++] = c++;
// 10C00..10C4F; Old Turkic
	c = 0x10c00;		// from OLD TURKIC LETTER ORKHON A
	while (c <= 0x10c48)	// ..to OLD TURKIC LETTER ORKHON BASH
		charset[i++] = c++;
// 10C80..10CFF; Old Hungarian
	c = 0x10c80;		// from OLD HUNGARIAN CAPITAL LETTER A
	while (c <= 0x10cb2)	// ..to OLD HUNGARIAN CAPITAL LETTER US
		charset[i++] = c++;
	c = 0x10cc0;		// from OLD HUNGARIAN SMALL LETTER A
	while (c <= 0x10cf2)	// ..to OLD HUNGARIAN SMALL LETTER US
		charset[i++] = c++;
	c = 0x10cfa;		// from OLD HUNGARIAN NUMBER ONE
	while (c <= 0x10cff)	// ..to OLD HUNGARIAN NUMBER ONE THOUSAND
		charset[i++] = c++;
// 10D00..10D3F; Hanifi Rohingya
	c = 0x10d00;		// from HANIFI ROHINGYA LETTER A
	while (c <= 0x10d27)	// ..to HANIFI ROHINGYA SIGN TASSI
		charset[i++] = c++;
	c = 0x10d30;		// from HANIFI ROHINGYA DIGIT ZERO
	while (c <= 0x10d39)	// ..to HANIFI ROHINGYA DIGIT NINE
		charset[i++] = c++;
// 10E60..10E7F; Rumi Numeral Symbols
	c = 0x10e60;		// from RUMI DIGIT ONE
	while (c <= 0x10e7e)	// ..to RUMI FRACTION TWO THIRDS
		charset[i++] = c++;
// 10E80..10EBF; Yezidi
	c = 0x10e80;		// from YEZIDI LETTER ELIF
	while (c <= 0x10ea9)	// ..to YEZIDI LETTER ET
		charset[i++] = c++;
	charset[i++] = 0x10eab;	// YEZIDI COMBINING HAMZA MARK
	charset[i++] = 0x10ead;	// YEZIDI HYPHENATION MARK
	charset[i++] = 0x10eb0;	// YEZIDI LETTER LAM WITH DOT ABOVE
	charset[i++] = 0x10eb1;	// YEZIDI LETTER YOT WITH CIRCUMFLEX ABOVE
// 10F00..10F2F; Old Sogdian
	c = 0x10f00;		// from OLD SOGDIAN LETTER ALEPH
	while (c <= 0x10f27)	// ..to OLD SOGDIAN LIGATURE AYIN-DALETH
		charset[i++] = c++;
// 10F30..10F6F; Sogdian
	c = 0x10f30;		// from SOGDIAN LETTER ALEPH
	while (c <= 0x10f59)	// ..to SOGDIAN PUNCTUATION HALF CIRCLE WITH DOT
		charset[i++] = c++;
// 10FB0..10FDF; Chorasmian
	c = 0x10fb0;		// from CHORASMIAN LETTER ALEPH
	while (c <= 0x10fcb)	// ..to CHORASMIAN NUMBER ONE HUNDRED
		charset[i++] = c++;
// 10FE0..10FFF; Elymaic
	c = 0x10fe0;		// from ELYMAIC LETTER ALEPH
	while (c <= 0x10ff6)	// ..to ELYMAIC LIGATURE ZAYIN-YODH
		charset[i++] = c++;
// 11000..1107F; Brahmi
	c = 0x11000;		// from BRAHMI SIGN CANDRABINDU
	while (c <= 0x1104d)	// ..to BRAHMI PUNCTUATION LOTUS
		charset[i++] = c++;
	c = 0x11052;		// from BRAHMI NUMBER ONE
	while (c <= 0x1106f)	// ..to BRAHMI DIGIT NINE
		charset[i++] = c++;
	charset[i++] = 0x1107f;	// BRAHMI NUMBER JOINER
// 11080..110CF; Kaithi
	c = 0x11080;		// from KAITHI SIGN CANDRABINDU
	while (c <= 0x110c1)	// ..to KAITHI DOUBLE DANDA
		charset[i++] = c++;
	charset[i++] = 0x110cd;	// KAITHI NUMBER SIGN ABOVE
// 110D0..110FF; Sora Sompeng
	c = 0x110d0;		// from SORA SOMPENG LETTER SAH
	while (c <= 0x110e8)	// ..to SORA SOMPENG LETTER MAE
		charset[i++] = c++;
	c = 0x110f0;		// from SORA SOMPENG DIGIT ZERO
	while (c <= 0x110f9)	// ..to SORA SOMPENG DIGIT NINE
		charset[i++] = c++;
// 11100..1114F; Chakma
	c = 0x11100;		// from CHAKMA SIGN CANDRABINDU
	while (c <= 0x11134)	// ..to CHAKMA MAAYYAA
		charset[i++] = c++;
	c = 0x11136;		// from CHAKMA DIGIT ZERO
	while (c <= 0x11147)	// ..to CHAKMA LETTER VAA
		charset[i++] = c++;
// 11150..1117F; Mahajani
	c = 0x11150;		// from MAHAJANI LETTER A
	while (c <= 0x11176)	// ..to MAHAJANI LIGATURE SHRI
		charset[i++] = c++;
// 11180..111DF; Sharada
	c = 0x11180;		// from SHARADA SIGN CANDRABINDU
	while (c <= 0x111df)	// ..to SHARADA SECTION MARK-2
		charset[i++] = c++;
// 111E0..111FF; Sinhala Archaic Numbers
	c = 0x111e1;		// from SINHALA ARCHAIC DIGIT ONE
	while (c <= 0x111f4)	// ..to SINHALA ARCHAIC NUMBER ONE THOUSAND
		charset[i++] = c++;
// 11200..1124F; Khojki
	c = 0x11200;		// from KHOJKI LETTER A
	while (c <= 0x11211)	// ..to KHOJKI LETTER JJA
		charset[i++] = c++;
	c = 0x11213;		// from KHOJKI LETTER NYA
	while (c <= 0x1123e)	// ..to KHOJKI SIGN SUKUN
		charset[i++] = c++;
// 11280..112AF; Multani
	c = 0x11280;		// from MULTANI LETTER A
	while (c <= 0x11286)	// ..to MULTANI LETTER GA
		charset[i++] = c++;
	c = 0x1128a;		// from MULTANI LETTER CA
	while (c <= 0x1128d)	// ..to MULTANI LETTER JJA
		charset[i++] = c++;
	c = 0x1128f;		// from MULTANI LETTER NYA
	while (c <= 0x1129d)	// ..to MULTANI LETTER BA
		charset[i++] = c++;
	c = 0x1129f;		// from MULTANI LETTER BHA
	while (c <= 0x112a9)	// ..to MULTANI SECTION MARK
		charset[i++] = c++;
// 112B0..112FF; Khudawadi
	c = 0x112b0;		// from KHUDAWADI LETTER A
	while (c <= 0x112ea)	// ..to KHUDAWADI SIGN VIRAMA
		charset[i++] = c++;
	c = 0x112f0;		// from KHUDAWADI DIGIT ZERO
	while (c <= 0x112f9)	// ..to KHUDAWADI DIGIT NINE
		charset[i++] = c++;
// 11300..1137F; Grantha
	c = 0x11300;		// from GRANTHA SIGN COMBINING ANUSVARA ABOVE
	while (c <= 0x11303)	// ..to GRANTHA SIGN VISARGA
		charset[i++] = c++;
	c = 0x11305;		// from GRANTHA LETTER A
	while (c <= 0x1130c)	// ..to GRANTHA LETTER VOCALIC L
		charset[i++] = c++;
	charset[i++] = 0x1130f;	// GRANTHA LETTER EE
	charset[i++] = 0x11310;	// GRANTHA LETTER AI
	c = 0x11313;		// from GRANTHA LETTER OO
	while (c <= 0x11328)	// ..to GRANTHA LETTER NA
		charset[i++] = c++;
	c = 0x1132a;		// from GRANTHA LETTER PA
	while (c <= 0x11330)	// ..to GRANTHA LETTER RA
		charset[i++] = c++;
	charset[i++] = 0x11332;	// GRANTHA LETTER LA
	charset[i++] = 0x11333;	// GRANTHA LETTER LLA
	c = 0x11335;		// from GRANTHA LETTER VA
	while (c <= 0x11339)	// ..to GRANTHA LETTER HA
		charset[i++] = c++;
	c = 0x1133b;		// from COMBINING BINDU BELOW
	while (c <= 0x11344)	// ..to GRANTHA VOWEL SIGN VOCALIC RR
		charset[i++] = c++;
	charset[i++] = 0x11347;	// GRANTHA VOWEL SIGN EE
	charset[i++] = 0x11348;	// GRANTHA VOWEL SIGN AI
	charset[i++] = 0x1134b;	// GRANTHA VOWEL SIGN OO
	charset[i++] = 0x1134d;	// GRANTHA SIGN VIRAMA
	c = 0x1135d;		// from GRANTHA SIGN PLUTA
	while (c <= 0x11363)	// ..to GRANTHA VOWEL SIGN VOCALIC LL
		charset[i++] = c++;
	c = 0x11366;		// from COMBINING GRANTHA DIGIT ZERO
	while (c <= 0x1136c)	// ..to COMBINING GRANTHA DIGIT SIX
		charset[i++] = c++;
	c = 0x11370;		// from COMBINING GRANTHA LETTER A
	while (c <= 0x11374)	// ..to COMBINING GRANTHA LETTER PA
		charset[i++] = c++;
// 11400..1147F; Newa
	c = 0x11400;		// from NEWA LETTER A
	while (c <= 0x1145b)	// ..to NEWA PLACEHOLDER MARK
		charset[i++] = c++;
	c = 0x1145d;		// from NEWA INSERTION SIGN
	while (c <= 0x11461)	// ..to NEWA SIGN UPADHMANIYA
		charset[i++] = c++;
// 11480..114DF; Tirhuta
	c = 0x11480;		// from TIRHUTA ANJI
	while (c <= 0x114c7)	// ..to TIRHUTA OM
		charset[i++] = c++;
	c = 0x114d0;		// from TIRHUTA DIGIT ZERO
	while (c <= 0x114d9)	// ..to TIRHUTA DIGIT NINE
		charset[i++] = c++;
// 11580..115FF; Siddham
	c = 0x11580;		// from SIDDHAM LETTER A
	while (c <= 0x115b5)	// ..to SIDDHAM VOWEL SIGN VOCALIC RR
		charset[i++] = c++;
	c = 0x115b8;		// from SIDDHAM VOWEL SIGN E
	while (c <= 0x115dd)	// ..to SIDDHAM VOWEL SIGN ALTERNATE UU
		charset[i++] = c++;
// 11600..1165F; Modi
	c = 0x11600;		// from MODI LETTER A
	while (c <= 0x11644)	// ..to MODI SIGN HUVA
		charset[i++] = c++;
	c = 0x11650;		// from MODI DIGIT ZERO
	while (c <= 0x11659)	// ..to MODI DIGIT NINE
		charset[i++] = c++;
// 11660..1167F; Mongolian Supplement
	c = 0x11660;		// from MONGOLIAN BIRGA WITH ORNAMENT
	while (c <= 0x1166c)	// ..to MONGOLIAN TURNED SWIRL BIRGA WITH DOUBLE ORNAMENT
		charset[i++] = c++;
// 11680..116CF; Takri
	c = 0x11680;		// from TAKRI LETTER A
	while (c <= 0x116b8)	// ..to TAKRI LETTER ARCHAIC KHA
		charset[i++] = c++;
	c = 0x116c0;		// from TAKRI DIGIT ZERO
	while (c <= 0x116c9)	// ..to TAKRI DIGIT NINE
		charset[i++] = c++;
// 11700..1173F; Ahom
	c = 0x11700;		// from AHOM LETTER KA
	while (c <= 0x1171a)	// ..to AHOM LETTER ALTERNATE BA
		charset[i++] = c++;
	c = 0x1171d;		// from AHOM CONSONANT SIGN MEDIAL LA
	while (c <= 0x1172b)	// ..to AHOM SIGN KILLER
		charset[i++] = c++;
	c = 0x11730;		// from AHOM DIGIT ZERO
	while (c <= 0x1173f)	// ..to AHOM SYMBOL VI
		charset[i++] = c++;
// 11800..1184F; Dogra
	c = 0x11800;		// from DOGRA LETTER A
	while (c <= 0x1183b)	// ..to DOGRA ABBREVIATION SIGN
		charset[i++] = c++;
// 118A0..118FF; Warang Citi
	c = 0x118a0;		// from WARANG CITI CAPITAL LETTER NGAA
	while (c <= 0x118f2)	// ..to WARANG CITI NUMBER NINETY
		charset[i++] = c++;
	charset[i++] = 0x118ff;	// WARANG CITI OM
// 11900..1195F; Dives Akuru
	c = 0x11900;		// from DIVES AKURU LETTER A
	while (c <= 0x11906)	// ..to DIVES AKURU LETTER E
		charset[i++] = c++;
	c = 0x1190c;		// from DIVES AKURU LETTER KA
	while (c <= 0x11913)	// ..to DIVES AKURU LETTER JA
		charset[i++] = c++;
	charset[i++] = 0x11915;	// DIVES AKURU LETTER NYA
	charset[i++] = 0x11916;	// DIVES AKURU LETTER TTA
	c = 0x11918;		// from DIVES AKURU LETTER DDA
	while (c <= 0x11935)	// ..to DIVES AKURU VOWEL SIGN E
		charset[i++] = c++;
	charset[i++] = 0x11937;	// DIVES AKURU VOWEL SIGN AI
	charset[i++] = 0x11938;	// DIVES AKURU VOWEL SIGN O
	c = 0x1193b;		// from DIVES AKURU SIGN ANUSVARA
	while (c <= 0x11946)	// ..to DIVES AKURU END OF TEXT MARK
		charset[i++] = c++;
	c = 0x11950;		// from DIVES AKURU DIGIT ZERO
	while (c <= 0x11959)	// ..to DIVES AKURU DIGIT NINE
		charset[i++] = c++;
// 119A0..119FF; Nandinagari
	c = 0x119a0;		// from NANDINAGARI LETTER A
	while (c <= 0x119a7)	// ..to NANDINAGARI LETTER VOCALIC RR
		charset[i++] = c++;
	c = 0x119aa;		// from NANDINAGARI LETTER E
	while (c <= 0x119d7)	// ..to NANDINAGARI VOWEL SIGN VOCALIC RR
		charset[i++] = c++;
	c = 0x119da;		// from NANDINAGARI VOWEL SIGN E
	while (c <= 0x119e4)	// ..to NANDINAGARI VOWEL SIGN PRISHTHAMATRA E
		charset[i++] = c++;
// 11A00..11A4F; Zanabazar Square
	c = 0x11a00;		// from ZANABAZAR SQUARE LETTER A
	while (c <= 0x11a47)	// ..to ZANABAZAR SQUARE SUBJOINER
		charset[i++] = c++;
// 11A50..11AAF; Soyombo
	c = 0x11a50;		// from SOYOMBO LETTER A
	while (c <= 0x11aa2)	// ..to SOYOMBO TERMINAL MARK-2
		charset[i++] = c++;
// 11AC0..11AFF; Pau Cin Hau
	c = 0x11ac0;		// from PAU CIN HAU LETTER PA
	while (c <= 0x11af8)	// ..to PAU CIN HAU GLOTTAL STOP FINAL
		charset[i++] = c++;
// 11C00..11C6F; Bhaiksuki
	c = 0x11c00;		// from BHAIKSUKI LETTER A
	while (c <= 0x11c08)	// ..to BHAIKSUKI LETTER VOCALIC L
		charset[i++] = c++;
	c = 0x11c0a;		// from BHAIKSUKI LETTER E
	while (c <= 0x11c36)	// ..to BHAIKSUKI VOWEL SIGN VOCALIC L
		charset[i++] = c++;
	c = 0x11c38;		// from BHAIKSUKI VOWEL SIGN E
	while (c <= 0x11c45)	// ..to BHAIKSUKI GAP FILLER-2
		charset[i++] = c++;
	c = 0x11c50;		// from BHAIKSUKI DIGIT ZERO
	while (c <= 0x11c6c)	// ..to BHAIKSUKI HUNDREDS UNIT MARK
		charset[i++] = c++;
// 11C70..11CBF; Marchen
	c = 0x11c70;		// from MARCHEN HEAD MARK
	while (c <= 0x11c8f)	// ..to MARCHEN LETTER A
		charset[i++] = c++;
	c = 0x11c92;		// from MARCHEN SUBJOINED LETTER KA
	while (c <= 0x11ca7)	// ..to MARCHEN SUBJOINED LETTER ZA
		charset[i++] = c++;
	c = 0x11ca9;		// from MARCHEN SUBJOINED LETTER YA
	while (c <= 0x11cb6)	// ..to MARCHEN SIGN CANDRABINDU
		charset[i++] = c++;
// 11D00..11D5F; Masaram Gondi
	c = 0x11d00;		// from MASARAM GONDI LETTER A
	while (c <= 0x11d06)	// ..to MASARAM GONDI LETTER E
		charset[i++] = c++;
	charset[i++] = 0x11d08;	// MASARAM GONDI LETTER AI
	charset[i++] = 0x11d09;	// MASARAM GONDI LETTER O
	c = 0x11d0b;		// from MASARAM GONDI LETTER AU
	while (c <= 0x11d36)	// ..to MASARAM GONDI VOWEL SIGN VOCALIC R
		charset[i++] = c++;
	charset[i++] = 0x11d3c;	// MASARAM GONDI VOWEL SIGN AI
	charset[i++] = 0x11d3d;	// MASARAM GONDI VOWEL SIGN O
	c = 0x11d3f;		// from MASARAM GONDI VOWEL SIGN AU
	while (c <= 0x11d47)	// ..to MASARAM GONDI RA-KARA
		charset[i++] = c++;
	c = 0x11d50;		// from MASARAM GONDI DIGIT ZERO
	while (c <= 0x11d59)	// ..to MASARAM GONDI DIGIT NINE
		charset[i++] = c++;
// 11D60..11DAF; Gunjala Gondi
	c = 0x11d60;		// from GUNJALA GONDI LETTER A
	while (c <= 0x11d65)	// ..to GUNJALA GONDI LETTER UU
		charset[i++] = c++;
	charset[i++] = 0x11d67;	// GUNJALA GONDI LETTER EE
	charset[i++] = 0x11d68;	// GUNJALA GONDI LETTER AI
	c = 0x11d6a;		// from GUNJALA GONDI LETTER OO
	while (c <= 0x11d8e)	// ..to GUNJALA GONDI VOWEL SIGN UU
		charset[i++] = c++;
	charset[i++] = 0x11d90;	// GUNJALA GONDI VOWEL SIGN EE
	charset[i++] = 0x11d91;	// GUNJALA GONDI VOWEL SIGN AI
	c = 0x11d93;		// from GUNJALA GONDI VOWEL SIGN OO
	while (c <= 0x11d98)	// ..to GUNJALA GONDI OM
		charset[i++] = c++;
	c = 0x11da0;		// from GUNJALA GONDI DIGIT ZERO
	while (c <= 0x11da9)	// ..to GUNJALA GONDI DIGIT NINE
		charset[i++] = c++;
// 11EE0..11EFF; Makasar
	c = 0x11ee0;		// from MAKASAR LETTER KA
	while (c <= 0x11ef8)	// ..to MAKASAR END OF SECTION
		charset[i++] = c++;
// 11FB0..11FBF; Lisu Supplement
	charset[i++] = 0x11fb0;	// LISU LETTER YHA
// 11FC0..11FFF; Tamil Supplement
	c = 0x11fc0;		// from TAMIL FRACTION ONE THREE-HUNDRED-AND-TWENTIETH
	while (c <= 0x11ff1)	// ..to TAMIL SIGN VAKAIYARAA
		charset[i++] = c++;
	charset[i++] = 0x11fff;	// TAMIL PUNCTUATION END OF TEXT
// 12000..123FF; Cuneiform
	c = 0x12000;		// from CUNEIFORM SIGN A
	while (c <= 0x12399)	// ..to CUNEIFORM SIGN U U
		charset[i++] = c++;
// 12400..1247F; Cuneiform Numbers and Punctuation
	c = 0x12400;		// from CUNEIFORM NUMERIC SIGN TWO ASH
	while (c <= 0x1246e)	// ..to CUNEIFORM NUMERIC SIGN NINE U VARIANT FORM
		charset[i++] = c++;
	c = 0x12470;		// from CUNEIFORM PUNCTUATION SIGN OLD ASSYRIAN WORD DIVIDER
	while (c <= 0x12474)	// ..to CUNEIFORM PUNCTUATION SIGN DIAGONAL QUADCOLON
		charset[i++] = c++;
// 12480..1254F; Early Dynastic Cuneiform
	c = 0x12480;		// from CUNEIFORM SIGN AB TIMES NUN TENU
	while (c <= 0x12543)	// ..to CUNEIFORM SIGN ZU5 TIMES THREE DISH TENU
		charset[i++] = c++;
// 13000..1342F; Egyptian Hieroglyphs
	c = 0x13000;		// from EGYPTIAN HIEROGLYPH A001
	while (c <= 0x1342e)	// ..to EGYPTIAN HIEROGLYPH AA032
		charset[i++] = c++;
// 13430..1343F; Egyptian Hieroglyph Format Controls
	c = 0x13430;		// from EGYPTIAN HIEROGLYPH VERTICAL JOINER
	while (c <= 0x13438)	// ..to EGYPTIAN HIEROGLYPH END SEGMENT
		charset[i++] = c++;
// 14400..1467F; Anatolian Hieroglyphs
	c = 0x14400;		// from ANATOLIAN HIEROGLYPH A001
	while (c <= 0x14646)	// ..to ANATOLIAN HIEROGLYPH A530
		charset[i++] = c++;
// 16800..16A3F; Bamum Supplement
	c = 0x16800;		// from BAMUM LETTER PHASE-A NGKUE MFON
	while (c <= 0x16a38)	// ..to BAMUM LETTER PHASE-F VUEQ
		charset[i++] = c++;
// 16A40..16A6F; Mro
	c = 0x16a40;		// from MRO LETTER TA
	while (c <= 0x16a5e)	// ..to MRO LETTER TEK
		charset[i++] = c++;
	c = 0x16a60;		// from MRO DIGIT ZERO
	while (c <= 0x16a69)	// ..to MRO DIGIT NINE
		charset[i++] = c++;
	charset[i++] = 0x16a6e;	// MRO DANDA
	charset[i++] = 0x16a6f;	// MRO DOUBLE DANDA
// 16AD0..16AFF; Bassa Vah
	c = 0x16ad0;		// from BASSA VAH LETTER ENNI
	while (c <= 0x16aed)	// ..to BASSA VAH LETTER I
		charset[i++] = c++;
	c = 0x16af0;		// from BASSA VAH COMBINING HIGH TONE
	while (c <= 0x16af5)	// ..to BASSA VAH FULL STOP
		charset[i++] = c++;
// 16B00..16B8F; Pahawh Hmong
	c = 0x16b00;		// from PAHAWH HMONG VOWEL KEEB
	while (c <= 0x16b45)	// ..to PAHAWH HMONG SIGN CIM TSOV ROG
		charset[i++] = c++;
	c = 0x16b50;		// from PAHAWH HMONG DIGIT ZERO
	while (c <= 0x16b59)	// ..to PAHAWH HMONG DIGIT NINE
		charset[i++] = c++;
	c = 0x16b5b;		// from PAHAWH HMONG NUMBER TENS
	while (c <= 0x16b61)	// ..to PAHAWH HMONG NUMBER TRILLIONS
		charset[i++] = c++;
	c = 0x16b63;		// from PAHAWH HMONG SIGN VOS LUB
	while (c <= 0x16b77)	// ..to PAHAWH HMONG SIGN CIM NRES TOS
		charset[i++] = c++;
	c = 0x16b7d;		// from PAHAWH HMONG CLAN SIGN TSHEEJ
	while (c <= 0x16b8f)	// ..to PAHAWH HMONG CLAN SIGN VWJ
		charset[i++] = c++;
// 16E40..16E9F; Medefaidrin
	c = 0x16e40;		// from MEDEFAIDRIN CAPITAL LETTER M
	while (c <= 0x16e9a)	// ..to MEDEFAIDRIN EXCLAMATION OH
		charset[i++] = c++;
// 16F00..16F9F; Miao
	c = 0x16f00;		// from MIAO LETTER PA
	while (c <= 0x16f4a)	// ..to MIAO LETTER RTE
		charset[i++] = c++;
	c = 0x16f4f;		// from MIAO SIGN CONSONANT MODIFIER BAR
	while (c <= 0x16f87)	// ..to MIAO VOWEL SIGN UI
		charset[i++] = c++;
	c = 0x16f8f;		// from MIAO TONE RIGHT
	while (c <= 0x16f9f)	// ..to MIAO LETTER REFORMED TONE-8
		charset[i++] = c++;
// 16FE0..16FFF; Ideographic Symbols and Punctuation
	c = 0x16fe0;		// from TANGUT ITERATION MARK
	while (c <= 0x16fe4)	// ..to KHITAN SMALL SCRIPT FILLER
		charset[i++] = c++;
	charset[i++] = 0x16ff0;	// VIETNAMESE ALTERNATE READING MARK CA
	charset[i++] = 0x16ff1;	// VIETNAMESE ALTERNATE READING MARK NHAY
// 17000..187FF; Tangut
	c = 0x17000;		// from <Tangut Ideograph, First>
	while (c <= 0x187f7)	// ..to <Tangut Ideograph, Last>
		charset[i++] = c++;
// 18800..18AFF; Tangut Components
	c = 0x18800;		// from TANGUT COMPONENT-001
	while (c <= 0x18aff)	// ..to TANGUT COMPONENT-768
		charset[i++] = c++;
// 18B00..18CFF; Khitan Small Script
	c = 0x18b00;		// from KHITAN SMALL SCRIPT CHARACTER-18B00
	while (c <= 0x18cd5)	// ..to KHITAN SMALL SCRIPT CHARACTER-18CD5
		charset[i++] = c++;
// 18D00..18D8F; Tangut Supplement
	c = 0x18d00;		// from <Tangut Ideograph Supplement, First>
	while (c <= 0x18d08)	// ..to <Tangut Ideograph Supplement, Last>
		charset[i++] = c++;
// 1B000..1B0FF; Kana Supplement
	c = 0x1b000;		// from KATAKANA LETTER ARCHAIC E
	while (c <= 0x1b0ff)	// ..to HENTAIGANA LETTER RE-2
		charset[i++] = c++;
// 1B100..1B12F; Kana Extended-A
	c = 0x1b100;		// from HENTAIGANA LETTER RE-3
	while (c <= 0x1b11e)	// ..to HENTAIGANA LETTER N-MU-MO-2
		charset[i++] = c++;
// 1B130..1B16F; Small Kana Extension
	charset[i++] = 0x1b150;	// HIRAGANA LETTER SMALL WI
	charset[i++] = 0x1b152;	// HIRAGANA LETTER SMALL WO
	c = 0x1b164;		// from KATAKANA LETTER SMALL WI
	while (c <= 0x1b167)	// ..to KATAKANA LETTER SMALL N
		charset[i++] = c++;
// 1B170..1B2FF; Nushu
	c = 0x1b170;		// from NUSHU CHARACTER-1B170
	while (c <= 0x1b2fb)	// ..to NUSHU CHARACTER-1B2FB
		charset[i++] = c++;
// 1BC00..1BC9F; Duployan
	c = 0x1bc00;		// from DUPLOYAN LETTER H
	while (c <= 0x1bc6a)	// ..to DUPLOYAN LETTER VOCALIC M
		charset[i++] = c++;
	c = 0x1bc70;		// from DUPLOYAN AFFIX LEFT HORIZONTAL SECANT
	while (c <= 0x1bc7c)	// ..to DUPLOYAN AFFIX ATTACHED TANGENT HOOK
		charset[i++] = c++;
	c = 0x1bc80;		// from DUPLOYAN AFFIX HIGH ACUTE
	while (c <= 0x1bc88)	// ..to DUPLOYAN AFFIX HIGH VERTICAL
		charset[i++] = c++;
	c = 0x1bc90;		// from DUPLOYAN AFFIX LOW ACUTE
	while (c <= 0x1bc99)	// ..to DUPLOYAN AFFIX LOW ARROW
		charset[i++] = c++;
	c = 0x1bc9c;		// from DUPLOYAN SIGN O WITH CROSS
	while (c <= 0x1bc9f)	// ..to DUPLOYAN PUNCTUATION CHINOOK FULL STOP
		charset[i++] = c++;
// 1BCA0..1BCAF; Shorthand Format Controls
	c = 0x1bca0;		// from SHORTHAND FORMAT LETTER OVERLAP
	while (c <= 0x1bca3)	// ..to SHORTHAND FORMAT UP STEP
		charset[i++] = c++;
// 1D000..1D0FF; Byzantine Musical Symbols
	c = 0x1d000;		// from BYZANTINE MUSICAL SYMBOL PSILI
	while (c <= 0x1d0f5)	// ..to BYZANTINE MUSICAL SYMBOL GORGON NEO KATO
		charset[i++] = c++;
// 1D100..1D1FF; Musical Symbols
	c = 0x1d100;		// from MUSICAL SYMBOL SINGLE BARLINE
	while (c <= 0x1d126)	// ..to MUSICAL SYMBOL DRUM CLEF-2
		charset[i++] = c++;
	c = 0x1d129;		// from MUSICAL SYMBOL MULTIPLE MEASURE REST
	while (c <= 0x1d1e8)	// ..to MUSICAL SYMBOL KIEVAN FLAT SIGN
		charset[i++] = c++;
// 1D200..1D24F; Ancient Greek Musical Notation
	c = 0x1d200;		// from GREEK VOCAL NOTATION SYMBOL-1
	while (c <= 0x1d245)	// ..to GREEK MUSICAL LEIMMA
		charset[i++] = c++;
// 1D2E0..1D2FF; Mayan Numerals
	c = 0x1d2e0;		// from MAYAN NUMERAL ZERO
	while (c <= 0x1d2f3)	// ..to MAYAN NUMERAL NINETEEN
		charset[i++] = c++;
// 1D300..1D35F; Tai Xuan Jing Symbols
	c = 0x1d300;		// from MONOGRAM FOR EARTH
	while (c <= 0x1d356)	// ..to TETRAGRAM FOR FOSTERING
		charset[i++] = c++;
// 1D360..1D37F; Counting Rod Numerals
	c = 0x1d360;		// from COUNTING ROD UNIT DIGIT ONE
	while (c <= 0x1d378)	// ..to TALLY MARK FIVE
		charset[i++] = c++;
// 1D400..1D7FF; Mathematical Alphanumeric Symbols
	c = 0x1d400;		// from MATHEMATICAL BOLD CAPITAL A
	while (c <= 0x1d454)	// ..to MATHEMATICAL ITALIC SMALL G
		charset[i++] = c++;
	c = 0x1d456;		// from MATHEMATICAL ITALIC SMALL I
	while (c <= 0x1d49c)	// ..to MATHEMATICAL SCRIPT CAPITAL A
		charset[i++] = c++;
	charset[i++] = 0x1d49e;	// MATHEMATICAL SCRIPT CAPITAL C
	charset[i++] = 0x1d49f;	// MATHEMATICAL SCRIPT CAPITAL D
	charset[i++] = 0x1d4a5;	// MATHEMATICAL SCRIPT CAPITAL J
	charset[i++] = 0x1d4a6;	// MATHEMATICAL SCRIPT CAPITAL K
	c = 0x1d4a9;		// from MATHEMATICAL SCRIPT CAPITAL N
	while (c <= 0x1d4ac)	// ..to MATHEMATICAL SCRIPT CAPITAL Q
		charset[i++] = c++;
	c = 0x1d4ae;		// from MATHEMATICAL SCRIPT CAPITAL S
	while (c <= 0x1d4b9)	// ..to MATHEMATICAL SCRIPT SMALL D
		charset[i++] = c++;
	c = 0x1d4bd;		// from MATHEMATICAL SCRIPT SMALL H
	while (c <= 0x1d4c3)	// ..to MATHEMATICAL SCRIPT SMALL N
		charset[i++] = c++;
	c = 0x1d4c5;		// from MATHEMATICAL SCRIPT SMALL P
	while (c <= 0x1d505)	// ..to MATHEMATICAL FRAKTUR CAPITAL B
		charset[i++] = c++;
	c = 0x1d507;		// from MATHEMATICAL FRAKTUR CAPITAL D
	while (c <= 0x1d50a)	// ..to MATHEMATICAL FRAKTUR CAPITAL G
		charset[i++] = c++;
	c = 0x1d50d;		// from MATHEMATICAL FRAKTUR CAPITAL J
	while (c <= 0x1d514)	// ..to MATHEMATICAL FRAKTUR CAPITAL Q
		charset[i++] = c++;
	c = 0x1d516;		// from MATHEMATICAL FRAKTUR CAPITAL S
	while (c <= 0x1d51c)	// ..to MATHEMATICAL FRAKTUR CAPITAL Y
		charset[i++] = c++;
	c = 0x1d51e;		// from MATHEMATICAL FRAKTUR SMALL A
	while (c <= 0x1d539)	// ..to MATHEMATICAL DOUBLE-STRUCK CAPITAL B
		charset[i++] = c++;
	c = 0x1d53b;		// from MATHEMATICAL DOUBLE-STRUCK CAPITAL D
	while (c <= 0x1d53e)	// ..to MATHEMATICAL DOUBLE-STRUCK CAPITAL G
		charset[i++] = c++;
	c = 0x1d540;		// from MATHEMATICAL DOUBLE-STRUCK CAPITAL I
	while (c <= 0x1d544)	// ..to MATHEMATICAL DOUBLE-STRUCK CAPITAL M
		charset[i++] = c++;
	c = 0x1d54a;		// from MATHEMATICAL DOUBLE-STRUCK CAPITAL S
	while (c <= 0x1d550)	// ..to MATHEMATICAL DOUBLE-STRUCK CAPITAL Y
		charset[i++] = c++;
	c = 0x1d552;		// from MATHEMATICAL DOUBLE-STRUCK SMALL A
	while (c <= 0x1d6a5)	// ..to MATHEMATICAL ITALIC SMALL DOTLESS J
		charset[i++] = c++;
	c = 0x1d6a8;		// from MATHEMATICAL BOLD CAPITAL ALPHA
	while (c <= 0x1d7cb)	// ..to MATHEMATICAL BOLD SMALL DIGAMMA
		charset[i++] = c++;
	c = 0x1d7ce;		// from MATHEMATICAL BOLD DIGIT ZERO
	while (c <= 0x1d7ff)	// ..to MATHEMATICAL MONOSPACE DIGIT NINE
		charset[i++] = c++;
// 1D800..1DAAF; Sutton SignWriting
	c = 0x1d800;		// from SIGNWRITING HAND-FIST INDEX
	while (c <= 0x1da8b)	// ..to SIGNWRITING PARENTHESIS
		charset[i++] = c++;
	c = 0x1da9b;		// from SIGNWRITING FILL MODIFIER-2
	while (c <= 0x1da9f)	// ..to SIGNWRITING FILL MODIFIER-6
		charset[i++] = c++;
	c = 0x1daa1;		// from SIGNWRITING ROTATION MODIFIER-2
	while (c <= 0x1daaf)	// ..to SIGNWRITING ROTATION MODIFIER-16
		charset[i++] = c++;
// 1E000..1E02F; Glagolitic Supplement
	c = 0x1e000;		// from COMBINING GLAGOLITIC LETTER AZU
	while (c <= 0x1e006)	// ..to COMBINING GLAGOLITIC LETTER ZHIVETE
		charset[i++] = c++;
	c = 0x1e008;		// from COMBINING GLAGOLITIC LETTER ZEMLJA
	while (c <= 0x1e018)	// ..to COMBINING GLAGOLITIC LETTER HERU
		charset[i++] = c++;
	c = 0x1e01b;		// from COMBINING GLAGOLITIC LETTER SHTA
	while (c <= 0x1e021)	// ..to COMBINING GLAGOLITIC LETTER YATI
		charset[i++] = c++;
	charset[i++] = 0x1e023;	// COMBINING GLAGOLITIC LETTER YU
	charset[i++] = 0x1e024;	// COMBINING GLAGOLITIC LETTER SMALL YUS
	c = 0x1e026;		// from COMBINING GLAGOLITIC LETTER YO
	while (c <= 0x1e02a)	// ..to COMBINING GLAGOLITIC LETTER FITA
		charset[i++] = c++;
// 1E100..1E14F; Nyiakeng Puachue Hmong
	c = 0x1e100;		// from NYIAKENG PUACHUE HMONG LETTER MA
	while (c <= 0x1e12c)	// ..to NYIAKENG PUACHUE HMONG LETTER W
		charset[i++] = c++;
	c = 0x1e130;		// from NYIAKENG PUACHUE HMONG TONE-B
	while (c <= 0x1e13d)	// ..to NYIAKENG PUACHUE HMONG SYLLABLE LENGTHENER
		charset[i++] = c++;
	c = 0x1e140;		// from NYIAKENG PUACHUE HMONG DIGIT ZERO
	while (c <= 0x1e149)	// ..to NYIAKENG PUACHUE HMONG DIGIT NINE
		charset[i++] = c++;
	charset[i++] = 0x1e14e;	// NYIAKENG PUACHUE HMONG LOGOGRAM NYAJ
	charset[i++] = 0x1e14f;	// NYIAKENG PUACHUE HMONG CIRCLED CA
// 1E2C0..1E2FF; Wancho
	c = 0x1e2c0;		// from WANCHO LETTER AA
	while (c <= 0x1e2f9)	// ..to WANCHO DIGIT NINE
		charset[i++] = c++;
	charset[i++] = 0x1e2ff;	// WANCHO NGUN SIGN
// 1E800..1E8DF; Mende Kikakui
	c = 0x1e800;		// from MENDE KIKAKUI SYLLABLE M001 KI
	while (c <= 0x1e8c4)	// ..to MENDE KIKAKUI SYLLABLE M060 NYON
		charset[i++] = c++;
	c = 0x1e8c7;		// from MENDE KIKAKUI DIGIT ONE
	while (c <= 0x1e8d6)	// ..to MENDE KIKAKUI COMBINING NUMBER MILLIONS
		charset[i++] = c++;
// 1E900..1E95F; Adlam
	c = 0x1e900;		// from ADLAM CAPITAL LETTER ALIF
	while (c <= 0x1e94b)	// ..to ADLAM NASALIZATION MARK
		charset[i++] = c++;
	c = 0x1e950;		// from ADLAM DIGIT ZERO
	while (c <= 0x1e959)	// ..to ADLAM DIGIT NINE
		charset[i++] = c++;
	charset[i++] = 0x1e95e;	// ADLAM INITIAL EXCLAMATION MARK
	charset[i++] = 0x1e95f;	// ADLAM INITIAL QUESTION MARK
// 1EC70..1ECBF; Indic Siyaq Numbers
	c = 0x1ec71;		// from INDIC SIYAQ NUMBER ONE
	while (c <= 0x1ecb4)	// ..to INDIC SIYAQ ALTERNATE LAKH MARK
		charset[i++] = c++;
// 1ED00..1ED4F; Ottoman Siyaq Numbers
	c = 0x1ed01;		// from OTTOMAN SIYAQ NUMBER ONE
	while (c <= 0x1ed3d)	// ..to OTTOMAN SIYAQ FRACTION ONE SIXTH
		charset[i++] = c++;
// 1EE00..1EEFF; Arabic Mathematical Alphabetic Symbols
	c = 0x1ee00;		// from ARABIC MATHEMATICAL ALEF
	while (c <= 0x1ee03)	// ..to ARABIC MATHEMATICAL DAL
		charset[i++] = c++;
	c = 0x1ee05;		// from ARABIC MATHEMATICAL WAW
	while (c <= 0x1ee1f)	// ..to ARABIC MATHEMATICAL DOTLESS QAF
		charset[i++] = c++;
	charset[i++] = 0x1ee21;	// ARABIC MATHEMATICAL INITIAL BEH
	charset[i++] = 0x1ee22;	// ARABIC MATHEMATICAL INITIAL JEEM
	c = 0x1ee29;		// from ARABIC MATHEMATICAL INITIAL YEH
	while (c <= 0x1ee32)	// ..to ARABIC MATHEMATICAL INITIAL QAF
		charset[i++] = c++;
	c = 0x1ee34;		// from ARABIC MATHEMATICAL INITIAL SHEEN
	while (c <= 0x1ee37)	// ..to ARABIC MATHEMATICAL INITIAL KHAH
		charset[i++] = c++;
	charset[i++] = 0x1ee4d;	// ARABIC MATHEMATICAL TAILED NOON
	charset[i++] = 0x1ee4f;	// ARABIC MATHEMATICAL TAILED AIN
	charset[i++] = 0x1ee51;	// ARABIC MATHEMATICAL TAILED SAD
	charset[i++] = 0x1ee52;	// ARABIC MATHEMATICAL TAILED QAF
	charset[i++] = 0x1ee61;	// ARABIC MATHEMATICAL STRETCHED BEH
	charset[i++] = 0x1ee62;	// ARABIC MATHEMATICAL STRETCHED JEEM
	c = 0x1ee67;		// from ARABIC MATHEMATICAL STRETCHED HAH
	while (c <= 0x1ee6a)	// ..to ARABIC MATHEMATICAL STRETCHED KAF
		charset[i++] = c++;
	c = 0x1ee6c;		// from ARABIC MATHEMATICAL STRETCHED MEEM
	while (c <= 0x1ee72)	// ..to ARABIC MATHEMATICAL STRETCHED QAF
		charset[i++] = c++;
	c = 0x1ee74;		// from ARABIC MATHEMATICAL STRETCHED SHEEN
	while (c <= 0x1ee77)	// ..to ARABIC MATHEMATICAL STRETCHED KHAH
		charset[i++] = c++;
	c = 0x1ee79;		// from ARABIC MATHEMATICAL STRETCHED DAD
	while (c <= 0x1ee7c)	// ..to ARABIC MATHEMATICAL STRETCHED DOTLESS BEH
		charset[i++] = c++;
	c = 0x1ee80;		// from ARABIC MATHEMATICAL LOOPED ALEF
	while (c <= 0x1ee89)	// ..to ARABIC MATHEMATICAL LOOPED YEH
		charset[i++] = c++;
	c = 0x1ee8b;		// from ARABIC MATHEMATICAL LOOPED LAM
	while (c <= 0x1ee9b)	// ..to ARABIC MATHEMATICAL LOOPED GHAIN
		charset[i++] = c++;
	charset[i++] = 0x1eea1;	// ARABIC MATHEMATICAL DOUBLE-STRUCK BEH
	charset[i++] = 0x1eea3;	// ARABIC MATHEMATICAL DOUBLE-STRUCK DAL
	c = 0x1eea5;		// from ARABIC MATHEMATICAL DOUBLE-STRUCK WAW
	while (c <= 0x1eea9)	// ..to ARABIC MATHEMATICAL DOUBLE-STRUCK YEH
		charset[i++] = c++;
	c = 0x1eeab;		// from ARABIC MATHEMATICAL DOUBLE-STRUCK LAM
	while (c <= 0x1eebb)	// ..to ARABIC MATHEMATICAL DOUBLE-STRUCK GHAIN
		charset[i++] = c++;
	charset[i++] = 0x1eef0;	// ARABIC MATHEMATICAL OPERATOR MEEM WITH HAH WITH TATWEEL
	charset[i++] = 0x1eef1;	// ARABIC MATHEMATICAL OPERATOR HAH WITH DAL
// 1F000..1F02F; Mahjong Tiles
	c = 0x1f000;		// from MAHJONG TILE EAST WIND
	while (c <= 0x1f02b)	// ..to MAHJONG TILE BACK
		charset[i++] = c++;
// 1F030..1F09F; Domino Tiles
	c = 0x1f030;		// from DOMINO TILE HORIZONTAL BACK
	while (c <= 0x1f093)	// ..to DOMINO TILE VERTICAL-06-06
		charset[i++] = c++;
// 1F0A0..1F0FF; Playing Cards
	c = 0x1f0a0;		// from PLAYING CARD BACK
	while (c <= 0x1f0ae)	// ..to PLAYING CARD KING OF SPADES
		charset[i++] = c++;
	c = 0x1f0b1;		// from PLAYING CARD ACE OF HEARTS
	while (c <= 0x1f0bf)	// ..to PLAYING CARD RED JOKER
		charset[i++] = c++;
	c = 0x1f0c1;		// from PLAYING CARD ACE OF DIAMONDS
	while (c <= 0x1f0cf)	// ..to PLAYING CARD BLACK JOKER
		charset[i++] = c++;
	c = 0x1f0d1;		// from PLAYING CARD ACE OF CLUBS
	while (c <= 0x1f0f5)	// ..to PLAYING CARD TRUMP-21
		charset[i++] = c++;
// 1F100..1F1FF; Enclosed Alphanumeric Supplement
	c = 0x1f100;		// from DIGIT ZERO FULL STOP
	while (c <= 0x1f1ad)	// ..to MASK WORK SYMBOL
		charset[i++] = c++;
	c = 0x1f1e6;		// from REGIONAL INDICATOR SYMBOL LETTER A
	while (c <= 0x1f1ff)	// ..to REGIONAL INDICATOR SYMBOL LETTER Z
		charset[i++] = c++;
// 1F200..1F2FF; Enclosed Ideographic Supplement
	charset[i++] = 0x1f200;	// SQUARE HIRAGANA HOKA
	charset[i++] = 0x1f202;	// SQUARED KATAKANA SA
	c = 0x1f210;		// from SQUARED CJK UNIFIED IDEOGRAPH-624B
	while (c <= 0x1f23b)	// ..to SQUARED CJK UNIFIED IDEOGRAPH-914D
		charset[i++] = c++;
	c = 0x1f240;		// from TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-672C
	while (c <= 0x1f248)	// ..to TORTOISE SHELL BRACKETED CJK UNIFIED IDEOGRAPH-6557
		charset[i++] = c++;
	charset[i++] = 0x1f250;	// CIRCLED IDEOGRAPH ADVANTAGE
	charset[i++] = 0x1f251;	// CIRCLED IDEOGRAPH ACCEPT
	c = 0x1f260;		// from ROUNDED SYMBOL FOR FU
	while (c <= 0x1f265)	// ..to ROUNDED SYMBOL FOR CAI
		charset[i++] = c++;
// 1F300..1F5FF; Miscellaneous Symbols and Pictographs
	c = 0x1f300;		// from CYCLONE
	while (c <= 0x1f5ff)	// ..to MOYAI
		charset[i++] = c++;
// 1F600..1F64F; Emoticons
	c = 0x1f600;		// from GRINNING FACE
	while (c <= 0x1f64f)	// ..to PERSON WITH FOLDED HANDS
		charset[i++] = c++;
// 1F650..1F67F; Ornamental Dingbats
	c = 0x1f650;		// from NORTH WEST POINTING LEAF
	while (c <= 0x1f67f)	// ..to REVERSE CHECKER BOARD
		charset[i++] = c++;
// 1F680..1F6FF; Transport and Map Symbols
	c = 0x1f680;		// from ROCKET
	while (c <= 0x1f6d7)	// ..to ELEVATOR
		charset[i++] = c++;
	c = 0x1f6e0;		// from HAMMER AND WRENCH
	while (c <= 0x1f6ec)	// ..to AIRPLANE ARRIVING
		charset[i++] = c++;
	c = 0x1f6f0;		// from SATELLITE
	while (c <= 0x1f6fc)	// ..to ROLLER SKATE
		charset[i++] = c++;
// 1F700..1F77F; Alchemical Symbols
	c = 0x1f700;		// from ALCHEMICAL SYMBOL FOR QUINTESSENCE
	while (c <= 0x1f773)	// ..to ALCHEMICAL SYMBOL FOR HALF OUNCE
		charset[i++] = c++;
// 1F780..1F7FF; Geometric Shapes Extended
	c = 0x1f780;		// from BLACK LEFT-POINTING ISOSCELES RIGHT TRIANGLE
	while (c <= 0x1f7d8)	// ..to NEGATIVE CIRCLED SQUARE
		charset[i++] = c++;
	c = 0x1f7e0;		// from LARGE ORANGE CIRCLE
	while (c <= 0x1f7eb)	// ..to LARGE BROWN SQUARE
		charset[i++] = c++;
// 1F800..1F8FF; Supplemental Arrows-C
	c = 0x1f800;		// from LEFTWARDS ARROW WITH SMALL TRIANGLE ARROWHEAD
	while (c <= 0x1f80b)	// ..to DOWNWARDS ARROW WITH LARGE TRIANGLE ARROWHEAD
		charset[i++] = c++;
	c = 0x1f810;		// from LEFTWARDS ARROW WITH SMALL EQUILATERAL ARROWHEAD
	while (c <= 0x1f847)	// ..to DOWNWARDS HEAVY ARROW
		charset[i++] = c++;
	c = 0x1f850;		// from LEFTWARDS SANS-SERIF ARROW
	while (c <= 0x1f859)	// ..to UP DOWN SANS-SERIF ARROW
		charset[i++] = c++;
	c = 0x1f860;		// from WIDE-HEADED LEFTWARDS LIGHT BARB ARROW
	while (c <= 0x1f887)	// ..to WIDE-HEADED SOUTH WEST VERY HEAVY BARB ARROW
		charset[i++] = c++;
	c = 0x1f890;		// from LEFTWARDS TRIANGLE ARROWHEAD
	while (c <= 0x1f8ad)	// ..to WHITE ARROW SHAFT WIDTH TWO THIRDS
		charset[i++] = c++;
	charset[i++] = 0x1f8b0;	// ARROW POINTING UPWARDS THEN NORTH WEST
	charset[i++] = 0x1f8b1;	// ARROW POINTING RIGHTWARDS THEN CURVING SOUTH WEST
// 1F900..1F9FF; Supplemental Symbols and Pictographs
	c = 0x1f900;		// from CIRCLED CROSS FORMEE WITH FOUR DOTS
	while (c <= 0x1f978)	// ..to DISGUISED FACE
		charset[i++] = c++;
	c = 0x1f97a;		// from FACE WITH PLEADING EYES
	while (c <= 0x1f9cb)	// ..to BUBBLE TEA
		charset[i++] = c++;
	c = 0x1f9cd;		// from STANDING PERSON
	while (c <= 0x1f9ff)	// ..to NAZAR AMULET
		charset[i++] = c++;
// 1FA00..1FA6F; Chess Symbols
	c = 0x1fa00;		// from NEUTRAL CHESS KING
	while (c <= 0x1fa53)	// ..to BLACK CHESS KNIGHT-BISHOP
		charset[i++] = c++;
	c = 0x1fa60;		// from XIANGQI RED GENERAL
	while (c <= 0x1fa6d)	// ..to XIANGQI BLACK SOLDIER
		charset[i++] = c++;
// 1FA70..1FAFF; Symbols and Pictographs Extended-A
	c = 0x1fa70;		// from BALLET SHOES
	while (c <= 0x1fa74)	// ..to THONG SANDAL
		charset[i++] = c++;
	charset[i++] = 0x1fa78;	// DROP OF BLOOD
	charset[i++] = 0x1fa7a;	// STETHOSCOPE
	c = 0x1fa80;		// from YO-YO
	while (c <= 0x1fa86)	// ..to NESTING DOLLS
		charset[i++] = c++;
	c = 0x1fa90;		// from RINGED PLANET
	while (c <= 0x1faa8)	// ..to ROCK
		charset[i++] = c++;
	c = 0x1fab0;		// from FLY
	while (c <= 0x1fab6)	// ..to FEATHER
		charset[i++] = c++;
	charset[i++] = 0x1fac0;	// ANATOMICAL HEART
	charset[i++] = 0x1fac2;	// PEOPLE HUGGING
	c = 0x1fad0;		// from BLUEBERRIES
	while (c <= 0x1fad6)	// ..to TEAPOT
		charset[i++] = c++;
// 1FB00..1FBFF; Symbols for Legacy Computing
	c = 0x1fb00;		// from BLOCK SEXTANT-1
	while (c <= 0x1fb92)	// ..to UPPER HALF INVERSE MEDIUM SHADE AND LOWER HALF BLOCK
		charset[i++] = c++;
	c = 0x1fb94;		// from LEFT HALF INVERSE MEDIUM SHADE AND RIGHT HALF BLOCK
	while (c <= 0x1fbca)	// ..to WHITE UP-POINTING CHEVRON
		charset[i++] = c++;
	c = 0x1fbf0;		// from SEGMENTED DIGIT ZERO
	while (c <= 0x1fbf9)	// ..to SEGMENTED DIGIT NINE
		charset[i++] = c++;
// 20000..2A6DF; CJK Unified Ideographs Extension B
	c = 0x20000;		// from <CJK Ideograph Extension B, First>
	while (c <= 0x2a6dd)	// ..to <CJK Ideograph Extension B, Last>
		charset[i++] = c++;
// 2A700..2B73F; CJK Unified Ideographs Extension C
	c = 0x2a700;		// from <CJK Ideograph Extension C, First>
	while (c <= 0x2b734)	// ..to <CJK Ideograph Extension C, Last>
		charset[i++] = c++;
// 2B740..2B81F; CJK Unified Ideographs Extension D
	c = 0x2b740;		// from <CJK Ideograph Extension D, First>
	while (c <= 0x2b81d)	// ..to <CJK Ideograph Extension D, Last>
		charset[i++] = c++;
// 2B820..2CEAF; CJK Unified Ideographs Extension E
	c = 0x2b820;		// from <CJK Ideograph Extension E, First>
	while (c <= 0x2cea1)	// ..to <CJK Ideograph Extension E, Last>
		charset[i++] = c++;
// 2CEB0..2EBEF; CJK Unified Ideographs Extension F
	c = 0x2ceb0;		// from <CJK Ideograph Extension F, First>
	while (c <= 0x2ebe0)	// ..to <CJK Ideograph Extension F, Last>
		charset[i++] = c++;
// 2F800..2FA1F; CJK Compatibility Ideographs Supplement
	c = 0x2f800;		// from CJK COMPATIBILITY IDEOGRAPH-2F800
	while (c <= 0x2fa1d)	// ..to CJK COMPATIBILITY IDEOGRAPH-2FA1D
		charset[i++] = c++;
// 30000..3134F; CJK Unified Ideographs Extension G
	c = 0x30000;		// from <CJK Ideograph Extension G, First>
	while (c <= 0x3134a)	// ..to <CJK Ideograph Extension G, Last>
		charset[i++] = c++;
// E0000..E007F; Tags
	c = 0xe0020;		// from TAG SPACE
	while (c <= 0xe007f)	// ..to CANCEL TAG
		charset[i++] = c++;
// E0100..E01EF; Variation Selectors Supplement
// F0000..FFFFF; Supplementary Private Use Area-A
// 100000..10FFFF; Supplementary Private Use Area-B

/* Zero-terminate it, and return actual length */
	charset[i] = 0;

	return i;
}
