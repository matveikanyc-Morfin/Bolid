package crypto

// Elligator2-маскировка эфемерных X25519-ключей в рукопожатии (дизайн
// 03-wire-format §2.2 / §7.1, профиль «look like nothing»).
//
// Задача: эфемерный публичный ключ в первом пакете не должен отличаться от
// равномерного случайного шума. Обычная точка X25519 распознаваема (лежит на
// кривой); Elligator2 отображает её в 32-байтовый «representative», статистически
// неотличимый от случайных байт. Получатель обратным отображением восстанавливает
// точку.
//
// КРИПТОГРАФИЯ — не самодельная: обратное отображение берётся из вычитанной
// BSD-библиотеки gitlab.com/yawning/edwards25519-extra/elligator2, арифметика —
// filippo.io/edwards25519 (BSD). Прямое отображение (encode) портировано из
// общедоступной реализации Loup Vaillant (Monocypher, CC-0/BSD-2) — того же
// первоисточника, что использует и obfs4. Корректность проверяется тестами
// (roundtrip encode→decode и полное рукопожатие Noise поверх этого слоя).
//
// ВАЖНО (кофактор): scalarBaseMultDirty НАМЕРЕННО не очищает кофактор, поэтому
// публичный ключ отличается от «обычного» X25519 на компоненту малого порядка.
// Это необходимо, чтобы representative был равномерным. На итоговый ECDH это не
// влияет: X25519 клампит скаляр (множитель 8) и убивает компоненту малого
// порядка, поэтому DH-секрет совпадает с обычным X25519. Обе стороны при этом
// подмешивают в Noise-транскрипт ИМЕННО этот «грязный» pub (см. ell2DH ниже).

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"gitlab.com/yawning/edwards25519-extra/elligator2"
)

// RepresentativeLen — длина Elligator2-representative (= длине X25519-ключа).
const RepresentativeLen = 32

// --- Полевые константы (математические факты, кодировка little-endian) ---

var (
	feOne = new(field.Element).One()

	feNegTwo = mustFieldElement([]byte{
		0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	})

	feA = mustFieldElementUint64(486662)

	feSqrtM1 = mustFieldElement([]byte{
		0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
		0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
	})

	// Edwards x-координата точки малого порядка: sqrt((sqrt(d+1)+1)/d).
	feLopX = mustFieldElement([]byte{
		0x4a, 0xd1, 0x45, 0xc5, 0x46, 0x46, 0xa1, 0xde, 0x38, 0xe2, 0xe5, 0x13, 0x70, 0x3c, 0x19, 0x5c,
		0xbb, 0x4a, 0xde, 0x38, 0x32, 0x99, 0x33, 0xe9, 0x28, 0x4a, 0x39, 0x06, 0xa0, 0xb9, 0xd5, 0x1f,
	})

	// Edwards y-координата точки малого порядка: -lop_x * sqrtm1.
	feLopY = mustFieldElement([]byte{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	})
)

func mustFieldElement(b []byte) *field.Element {
	fe, err := new(field.Element).SetBytes(b)
	if err != nil {
		panic("crypto/ell2: некорректная константа: " + err.Error())
	}
	return fe
}

func mustFieldElementUint64(x uint64) *field.Element {
	var b [32]byte
	binary.LittleEndian.PutUint64(b[:], x)
	return mustFieldElement(b[:])
}

// selectLowOrderPoint выбирает координату точки малого порядка по битам cofactor
// (константно-временно), повторяя логику Monocypher.
func selectLowOrderPoint(out, x, k *field.Element, cofactor uint8) {
	out.Zero()
	out.Select(k, out, int((cofactor>>1)&1)) // бит 1
	out.Select(x, out, int((cofactor>>0)&1)) // бит 0
	var tmp field.Element
	tmp.Negate(out)
	out.Select(&tmp, out, int((cofactor>>2)&1)) // бит 2
}

// scalarBaseMultDirty умножает базовую точку на скаляр и ДОБАВЛЯЕТ точку малого
// порядка (см. примечание о кофакторе в шапке файла), возвращая Montgomery
// u-координату результата.
func scalarBaseMultDirty(privateKey *[32]byte) *field.Element {
	scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(privateKey[:])
	if err != nil {
		panic("crypto/ell2: некорректный скаляр: " + err.Error())
	}
	pk := new(edwards25519.Point).ScalarBaseMult(scalar)

	var lopX, lopY, lopT field.Element
	selectLowOrderPoint(&lopX, feLopX, feSqrtM1, privateKey[0])
	selectLowOrderPoint(&lopY, feLopY, feOne, privateKey[0]+2)
	lopT.Multiply(&lopX, &lopY)
	lop, err := new(edwards25519.Point).SetExtendedCoordinates(&lopX, &lopY, feOne, &lopT)
	if err != nil {
		panic("crypto/ell2: не удалось построить точку малого порядка: " + err.Error())
	}
	pk.Add(pk, lop)

	// Edwards (x,y) → Montgomery u = (Z+Y)/(Z-Y); знак игнорируем.
	_, yExt, zExt, _ := pk.ExtendedCoordinates()
	var t1, t2 field.Element
	t1.Add(zExt, yExt)
	t2.Subtract(zExt, yExt)
	t2.Invert(&t2)
	t1.Multiply(&t1, &t2)
	return &t1
}

// uToRepresentative кодирует Montgomery u-координату в Elligator2-representative.
// Возвращает false, если у точки нет representative (≈ половина случаев — это
// нормально, вызывающий перегенерирует ключ). tweak задаёт две случайные старшие
// «паддинг»-бита и выбор ветви.
func uToRepresentative(representative *[32]byte, u *field.Element, tweak byte) bool {
	t1 := new(field.Element).Set(u)
	t2 := new(field.Element).Add(t1, feA)
	t3 := new(field.Element).Multiply(t1, t2)
	t3.Multiply(t3, feNegTwo)
	if _, isSquare := t3.SqrtRatio(feOne, t3); isSquare == 1 {
		t1.Select(t2, t1, int(tweak&1))
		t3.Multiply(t1, t3)
		t1.Mult32(t3, 2)
		t2.Negate(t3)
		tmp := t1.Bytes()
		t3.Select(t2, t3, int(tmp[0]&1))
		copy(representative[:], t3.Bytes())
		// Дополняем двумя случайными старшими битами (representative — 254 бита).
		representative[31] |= tweak & 0xc0
		return true
	}
	return false
}

// scalarBaseMult вычисляет «грязный» X25519-pub и его Elligator2-representative.
// Возвращает false примерно для половины приватных ключей (нет representative).
// privateKey ДОЛЖЕН быть полными 32 байтами энтропии (клампинг до вызова сделал
// бы representative неравномерным).
func scalarBaseMult(publicKey, representative, privateKey *[32]byte, tweak byte) bool {
	u := scalarBaseMultDirty(privateKey)
	if !uToRepresentative(representative, u, tweak) {
		return false
	}
	copy(publicKey[:], u.Bytes())
	return true
}

// RepresentativeToPublic восстанавливает «грязный» X25519-pub из representative
// (обратное Elligator2-отображение из BSD-библиотеки). Используется получателем
// перед обработкой Noise-сообщения.
func RepresentativeToPublic(representative []byte) []byte {
	// Representative закодирован в 254 битах: гасим две старшие «паддинг»-бита.
	var clamped [32]byte
	copy(clamped[:], representative)
	clamped[31] &= 63

	fe, err := new(field.Element).SetBytes(clamped[:])
	if err != nil {
		// Невозможно: длина уже 32 байта.
		panic("crypto/ell2: representative не 32 байта: " + err.Error())
	}
	u, _ := elligator2.MontgomeryFlavor(fe)
	return u.Bytes()
}

// --- Интеграция с Noise: DHFunc с Elligator2-эфемералами ---

// ephemeralCapture перехватывает representative эфемерного ключа, сгенерированного
// внутри flynn/noise (которая сама создаёт эфемерал и нам его наружу не отдаёт).
type ephemeralCapture struct {
	repr [RepresentativeLen]byte
	have bool
}

// ell2DH — обёртка DHFunc поверх X25519: GenerateKeypair выдаёт «грязный» pub и
// запоминает его representative; DH остаётся стандартным X25519 (клампинг убивает
// добавленную компоненту малого порядка, поэтому секрет совпадает с обычным).
type ell2DH struct {
	cap *ephemeralCapture
}

func (d ell2DH) GenerateKeypair(rng io.Reader) (noise.DHKey, error) {
	if rng == nil {
		rng = rand.Reader
	}
	for {
		var priv [32]byte
		if _, err := io.ReadFull(rng, priv[:]); err != nil {
			return noise.DHKey{}, err
		}
		var tweak [1]byte
		if _, err := io.ReadFull(rng, tweak[:]); err != nil {
			return noise.DHKey{}, err
		}
		var pub, repr [32]byte
		if scalarBaseMult(&pub, &repr, &priv, tweak[0]) {
			if d.cap != nil {
				d.cap.repr = repr
				d.cap.have = true
			}
			return noise.DHKey{Private: priv[:], Public: pub[:]}, nil
		}
		// Нет representative — пробуем другой ключ (rejection sampling).
	}
}

func (ell2DH) DH(privkey, pubkey []byte) ([]byte, error) {
	return curve25519.X25519(privkey, pubkey)
}

func (ell2DH) DHLen() int     { return 32 }
func (ell2DH) DHName() string { return "25519" } // тот же протокол-нейм, DH = X25519

// HandshakeSuite — криптонабор для одной стороны рукопожатия с Elligator2.
// Создаётся на каждое рукопожатие (capture не переиспользуется).
type HandshakeSuite struct {
	Suite noise.CipherSuite
	cap   *ephemeralCapture
}

// NewHandshakeSuite строит набор Noise, эквивалентный Suite, но с Elligator2-
// эфемералами. Возвращаемый набор передаётся в noise.Config.CipherSuite.
func NewHandshakeSuite() *HandshakeSuite {
	cap := &ephemeralCapture{}
	suite := noise.NewCipherSuite(ell2DH{cap: cap}, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	return &HandshakeSuite{Suite: suite, cap: cap}
}

// EphemeralRepresentative возвращает representative эфемерного ключа, который
// flynn/noise сгенерировала в последнем WriteMessage этой стороны. Вызывающий
// заменяет им «сырые» 32 байта эфемерала на проводе.
func (h *HandshakeSuite) EphemeralRepresentative() ([RepresentativeLen]byte, bool) {
	return h.cap.repr, h.cap.have
}
