// Package replay реализует защиту от повторов (anti-replay) на основе
// скользящего окна по 64-битному счётчику пакетов.
//
// Подход — классический bitmap-фильтр в духе IPsec / RFC 6479 и WireGuard:
// получатель помнит наибольший принятый счётчик (highest) и битовую карту
// последних W счётчиков. Это позволяет принимать пакеты с переупорядочиванием
// (необходимо для UDP), но отвергать дубликаты и воспроизведённые пакеты.
//
// Счётчик НИКОГДА не должен повторяться в рамках одного ключа сессии (он же —
// nonce для AEAD), поэтому отправитель монотонно увеличивает его, а получатель
// проверяет свежесть через Filter.
package replay

// DefaultWindowBits — размер окна по умолчанию (см. дизайн 03-wire-format §4.2).
// 8192 счётчика допускают значительное переупорядочивание на быстрых линиях.
const DefaultWindowBits = 8192

const wordBits = 64

// Filter — потоко-НЕбезопасный фильтр повторов для одного направления сессии.
// Синхронизацию (если нужна) обеспечивает вызывающий код.
type Filter struct {
	highest uint64   // наибольший принятый счётчик
	bitmap  []uint64 // битовая карта: бит (seq % bits) == 1 → seq уже виден
	bits    uint64   // размер окна в битах (кратен 64)
	started bool     // принят ли хотя бы один пакет
}

// New создаёт фильтр с окном не меньше windowBits (округляется вверх до кратного 64).
// При windowBits == 0 используется DefaultWindowBits.
func New(windowBits uint64) *Filter {
	if windowBits == 0 {
		windowBits = DefaultWindowBits
	}
	words := (windowBits + wordBits - 1) / wordBits
	if words == 0 {
		words = 1
	}
	return &Filter{
		bitmap: make([]uint64, words),
		bits:   words * wordBits,
	}
}

// WindowBits возвращает фактический размер окна в битах.
func (f *Filter) WindowBits() uint64 { return f.bits }

// ValidateAndAdd проверяет счётчик seq и, если он свежий, фиксирует его как
// принятый. Возвращает true, если пакет следует принять, и false — если это
// дубликат, повтор или слишком старый пакет (вне окна).
//
// Семантика «check-and-set» атомарна на уровне одного вызова: повторный вызов
// с тем же seq вернёт false.
func (f *Filter) ValidateAndAdd(seq uint64) bool {
	// Самый первый пакет задаёт начало окна.
	if !f.started {
		f.started = true
		f.highest = seq
		f.setBit(seq)
		return true
	}

	if seq > f.highest {
		// Счётчик продвигается вперёд — сдвигаем окно.
		diff := seq - f.highest
		if diff >= f.bits {
			// Скачок больше окна — все старые отметки больше не релевантны.
			for i := range f.bitmap {
				f.bitmap[i] = 0
			}
		} else {
			// Очищаем слоты для всех новых (ещё не виденных) позиций в (highest, seq].
			for s := f.highest + 1; s <= seq; s++ {
				f.clearBit(s)
			}
		}
		f.highest = seq
		f.setBit(seq)
		return true
	}

	// seq <= highest: пакет в прошлом относительно максимума.
	if f.highest-seq >= f.bits {
		return false // ниже окна — считаем устаревшим
	}
	if f.getBit(seq) {
		return false // уже видели этот счётчик — повтор/дубликат
	}
	f.setBit(seq)
	return true
}

func (f *Filter) index(seq uint64) (word, bit uint64) {
	pos := seq % f.bits
	return pos / wordBits, pos % wordBits
}

func (f *Filter) setBit(seq uint64) {
	w, b := f.index(seq)
	f.bitmap[w] |= 1 << b
}

func (f *Filter) clearBit(seq uint64) {
	w, b := f.index(seq)
	f.bitmap[w] &^= 1 << b
}

func (f *Filter) getBit(seq uint64) bool {
	w, b := f.index(seq)
	return f.bitmap[w]&(1<<b) != 0
}
