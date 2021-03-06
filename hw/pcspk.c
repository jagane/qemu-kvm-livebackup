/*
 * QEMU PC speaker emulation
 *
 * Copyright (c) 2006 Joachim Henke
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "hw.h"
#include "pc.h"
#include "isa.h"
#include "audio/audio.h"
#include "qemu-timer.h"
#include "i8254.h"
#include "qemu-kvm.h"

#define PCSPK_BUF_LEN 1792
#define PCSPK_SAMPLE_RATE 32000
#define PCSPK_MAX_FREQ (PCSPK_SAMPLE_RATE >> 1)
#define PCSPK_MIN_COUNT ((PIT_FREQ + PCSPK_MAX_FREQ - 1) / PCSPK_MAX_FREQ)

typedef struct {
    uint8_t sample_buf[PCSPK_BUF_LEN];
    QEMUSoundCard card;
    SWVoiceOut *voice;
    ISADevice *pit;
    unsigned int pit_count;
    unsigned int samples;
    unsigned int play_pos;
    int data_on;
    int dummy_refresh_clock;
} PCSpkState;

static const char *s_spk = "pcspk";
static PCSpkState pcspk_state;

#ifdef CONFIG_KVM_PIT
static void kvm_get_pit_ch2(ISADevice *dev,
                            struct kvm_pit_state *inkernel_state)
{
    struct PITState *pit = DO_UPCAST(struct PITState, dev, dev);
    struct kvm_pit_state pit_state;

    if (kvm_enabled() && kvm_pit_in_kernel()) {
        kvm_get_pit(kvm_context, &pit_state);
        pit->channels[2].mode = pit_state.channels[2].mode;
        pit->channels[2].count = pit_state.channels[2].count;
        pit->channels[2].count_load_time = pit_state.channels[2].count_load_time;
        pit->channels[2].gate = pit_state.channels[2].gate;
        if (inkernel_state) {
            memcpy(inkernel_state, &pit_state, sizeof(*inkernel_state));
        }
    }
}

static void kvm_set_pit_ch2(ISADevice *dev,
                            struct kvm_pit_state *inkernel_state)
{
    struct PITState *pit = DO_UPCAST(struct PITState, dev, dev);

    if (kvm_enabled() && kvm_pit_in_kernel()) {
        inkernel_state->channels[2].mode = pit->channels[2].mode;
        inkernel_state->channels[2].count = pit->channels[2].count;
        inkernel_state->channels[2].count_load_time =
            pit->channels[2].count_load_time;
        inkernel_state->channels[2].gate = pit->channels[2].gate;
        kvm_set_pit(kvm_context, inkernel_state);
    }
}
#else
static inline void kvm_get_pit_ch2(ISADevice *dev,
                                   struct kvm_pit_state *inkernel_state) { }
static inline void kvm_set_pit_ch2(ISADevice *dev,
                                   struct kvm_pit_state *inkernel_state) { }
#endif

static inline void generate_samples(PCSpkState *s)
{
    unsigned int i;

    if (s->pit_count) {
        const uint32_t m = PCSPK_SAMPLE_RATE * s->pit_count;
        const uint32_t n = ((uint64_t)PIT_FREQ << 32) / m;

        /* multiple of wavelength for gapless looping */
        s->samples = (PCSPK_BUF_LEN * PIT_FREQ / m * m / (PIT_FREQ >> 1) + 1) >> 1;
        for (i = 0; i < s->samples; ++i)
            s->sample_buf[i] = (64 & (n * i >> 25)) - 32;
    } else {
        s->samples = PCSPK_BUF_LEN;
        for (i = 0; i < PCSPK_BUF_LEN; ++i)
            s->sample_buf[i] = 128; /* silence */
    }
}

static void pcspk_callback(void *opaque, int free)
{
    PCSpkState *s = opaque;
    unsigned int n;

    kvm_get_pit_ch2(s->pit, NULL);

    if (pit_get_mode(s->pit, 2) != 3)
        return;

    n = pit_get_initial_count(s->pit, 2);
    /* avoid frequencies that are not reproducible with sample rate */
    if (n < PCSPK_MIN_COUNT)
        n = 0;

    if (s->pit_count != n) {
        s->pit_count = n;
        s->play_pos = 0;
        generate_samples(s);
    }

    while (free > 0) {
        n = audio_MIN(s->samples - s->play_pos, (unsigned int)free);
        n = AUD_write(s->voice, &s->sample_buf[s->play_pos], n);
        if (!n)
            break;
        s->play_pos = (s->play_pos + n) % s->samples;
        free -= n;
    }
}

int pcspk_audio_init(qemu_irq *pic)
{
    PCSpkState *s = &pcspk_state;
    struct audsettings as = {PCSPK_SAMPLE_RATE, 1, AUD_FMT_U8, 0};

    AUD_register_card(s_spk, &s->card);

    s->voice = AUD_open_out(&s->card, s->voice, s_spk, s, pcspk_callback, &as);
    if (!s->voice) {
        AUD_log(s_spk, "Could not open voice\n");
        return -1;
    }

    return 0;
}

static uint32_t pcspk_ioport_read(void *opaque, uint32_t addr)
{
    PCSpkState *s = opaque;
    int out;

    kvm_get_pit_ch2(s->pit, NULL);

    s->dummy_refresh_clock ^= (1 << 4);
    out = pit_get_out(s->pit, 2, qemu_get_clock_ns(vm_clock)) << 5;

    return pit_get_gate(s->pit, 2) | (s->data_on << 1) | s->dummy_refresh_clock | out;
}

static void pcspk_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
    struct kvm_pit_state inkernel_state;
    PCSpkState *s = opaque;
    const int gate = val & 1;

    kvm_get_pit_ch2(s->pit, &inkernel_state);

    s->data_on = (val >> 1) & 1;
    pit_set_gate(s->pit, 2, gate);
    if (s->voice) {
        if (gate) /* restart */
            s->play_pos = 0;
        AUD_set_active_out(s->voice, gate & s->data_on);
    }

    kvm_set_pit_ch2(s->pit, &inkernel_state);
}

void pcspk_init(ISADevice *pit)
{
    PCSpkState *s = &pcspk_state;

    s->pit = pit;
    register_ioport_read(0x61, 1, 1, pcspk_ioport_read, s);
    register_ioport_write(0x61, 1, 1, pcspk_ioport_write, s);
}
