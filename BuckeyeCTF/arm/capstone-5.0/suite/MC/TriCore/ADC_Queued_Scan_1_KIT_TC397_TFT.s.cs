# CS_ARCH_TRICORE, CS_MODE_TRICORE_162, None
0xdf,0x0f,0x08,0x82 = jne	d15, #0, #0x410
0x91,0x10,0x00,0x25 = movh.a	a2, #0x5001
0x6d,0xff,0xef,0xfb = call	#-0x822
0x3f,0xf1,0xef,0x7f = jlt	d1, d15, #-0x22
0x01,0xd0,0x00,0x26 = addsc.a	a2, a13, d0, #0
0x8f,0x24,0x40,0xf1 = or	d15, d4, #0x2
0xbe,0x6a           = jeq	d15, d6, #0x34
0x3c,0x64           = j	#0xc8
0x4b,0x0f,0x41,0xf0 = mul.f	d15, d15, d0
0x37,0x0f,0x04,0xf0 = insert	d15, d15, d0, #0, #0x4
0x10,0xe5           = addsc.a	a5, a14, d15, #0
0x37,0x00,0x48,0xf0 = extr	d15, d0, #0, #0x8
0xd9,0xff,0x28,0xa6 = lea	a15, [a15]#0x62a8
0x3c,0x08           = j	#0x10
0x37,0x0f,0x81,0xff = insert	d15, d15, d0, #0x1f, #0x1
0x37,0x03,0x68,0xf4 = extr.u	d15, d3, #0x8, #0x8
0x37,0xf3,0x08,0x34 = insert	d3, d3, d15, #0x8, #0x8
0x80,0x4f           = mov.d	d15, a4
0xd9,0x00,0x00,0x00 = lea	a0, [a0]#0
0x9a,0xd4           = add	d15, d4, #-0x3
0x9a,0x20           = add	d15, d0, #0x2
0xef,0x8f,0x0a,0x00 = jz.t	d15, #0x18, #0x14
0xd9,0xff,0xc0,0x09 = lea	a15, [a15]#-0x6400
0xd9,0x3f,0x0c,0x96 = lea	a15, [a3]#0x624c
0x37,0xf0,0x03,0x04 = insert	d0, d0, d15, #0x8, #0x3
0x3b,0x00,0x00,0x01 = mov	d0, #0x1000
0xee,0x05           = jnz	d15, #0xa
0x8f,0xff,0x83,0x21 = xor	d2, d15, #0x3f
0x6d,0xff,0x9c,0xf8 = call	#-0xec8
0x37,0x0f,0x01,0xf1 = insert	d15, d15, d0, #0x2, #0x1
0x3c,0x09           = j	#0x12
0x4b,0xf0,0x11,0x02 = div.u	e0, d0, d15
0x6f,0x10,0xf8,0x7f = jz.t	d0, #0x1, #-0x10
0xdf,0x1f,0x23,0x80 = jne	d15, #0x1, #0x46
0x76,0xc5           = jz	d12, #0xa
0x06,0xef           = sh	d15, #-0x2
0x8f,0xff,0x83,0x81 = xor	d8, d15, #0x3f
0x40,0x4c           = mov.aa	a12, a4
0x80,0xff           = mov.d	d15, a15
0x6f,0x0f,0xff,0x7f = jz.t	d15, #0, #-0x2
0x3c,0x0b           = j	#0x16
0x8f,0xff,0x83,0x31 = xor	d3, d15, #0x3f
0x09,0xff,0xc4,0x08 = ld.hu	d15, [a15]#0x4
0x9b,0x10,0x13,0x00 = addih	d0, d0, #0x131
0x49,0x40,0x40,0x08 = ldmst	[a4]#0, e0
0x8f,0xff,0x83,0x91 = xor	d9, d15, #0x3f
0x02,0x24           = mov	d4, d2
0x37,0x0f,0x02,0xfe = insert	d15, d15, d0, #0x1c, #0x2
0x8b,0x09,0x01,0xf0 = add	d15, d9, #0x10
0x60,0xff           = mov.a	a15, d15
0x6d,0xff,0xab,0xfb = call	#-0x8aa
0xd9,0xff,0x68,0x00 = lea	a15, [a15]#0x428
0xc2,0x19           = add	d9, #0x1
0xa2,0x1f           = sub	d15, d1
0x80,0xf0           = mov.d	d0, a15
0xbe,0x41           = jeq	d15, d4, #0x22
0x10,0xe2           = addsc.a	a2, a14, d15, #0
0x10,0x2f           = addsc.a	a15, a2, d15, #0
0x49,0x55,0x0c,0x0a = lea	a5, [a5]#0xc
0x06,0x50           = sh	d0, #0x5
0xf6,0x24           = jnz	d2, #0x8
0xfc,0xf6           = loop	a15, #-0x14
0x37,0x00,0x62,0xfe = extr.u	d15, d0, #0x1c, #0x2
0x6d,0xb8,0xf4,0x11 = call	#-0x8fdc18
0x91,0x00,0x03,0xfa = movh.a	a15, #0xa030
0x3b,0x20,0xfe,0x0f = mov	d0, #-0x1e
0x37,0x00,0x61,0x03 = extr.u	d0, d0, #0x6, #0x1
0xda,0x08           = mov	d15, #0x8
0x60,0xf2           = mov.a	a2, d15
0x6d,0x00,0x15,0x00 = call	#0x2a
0x80,0xf2           = mov.d	d2, a15
0x6d,0x00,0x91,0x00 = call	#0x122
0x3e,0x06           = jeq	d15, d0, #0xc
0x8f,0xff,0x83,0x11 = xor	d1, d15, #0x3f
0x91,0x40,0x00,0xf7 = movh.a	a15, #0x7004
0x53,0x40,0x20,0xf0 = mul	d15, d0, #0x4
0xc6,0x1f           = xor	d15, d1
0x3b,0x90,0xd0,0x03 = mov	d0, #0x3d09
0x3b,0xf0,0x05,0x20 = mov	d2, #0x5f
0x6d,0xff,0x57,0xfc = call	#-0x752
0xdf,0x1f,0x7f,0x80 = jne	d15, #0x1, #0xfe
0xd9,0xff,0x88,0x72 = lea	a15, [a15]#0x29c8
0x6d,0xff,0xb8,0xff = call	#-0x90
0xd9,0x44,0x0c,0x96 = lea	a4, [a4]#0x624c
0x1e,0x12           = jeq	d15, #0x1, #0x4
0x82,0xf1           = mov	d1, #-0x1
0x7f,0x0f,0x04,0x80 = jge.u	d15, d0, #0x8
0x8b,0xff,0x21,0xf3 = min.u	d15, d15, #0x1f
0x37,0x01,0x68,0xfc = extr.u	d15, d1, #0x18, #0x8
0x7b,0x00,0x00,0x0d = movh	d0, #0xd000
0x4b,0x0f,0x41,0x00 = mul.f	d0, d15, d0
0xb0,0x4c           = add.a	a12, #0x4
0xda,0x01           = mov	d15, #0x1
0x96,0x01           = or	d15, #0x1
0xdf,0x00,0x2e,0x00 = jeq	d0, #0, #0x5c
0xde,0x1c           = jne	d15, #0x1, #0x38
0x10,0xff           = addsc.a	a15, a15, d15, #0
0x82,0x21           = mov	d1, #0x2
0x96,0x04           = or	d15, #0x4
0x53,0x41,0x20,0xf0 = mul	d15, d1, #0x4
0x53,0x88,0x20,0xf0 = mul	d15, d8, #0x8
0x37,0x4f,0x82,0xf6 = insert	d15, d15, d4, #0xd, #0x2
0xd9,0xff,0x00,0x40 = lea	a15, [a15]#0x100
0x37,0xf0,0x02,0x02 = insert	d0, d0, d15, #0x4, #0x2
0x37,0x01,0x81,0x00 = insert	d0, d1, d0, #0x1, #0x1
0x80,0xdf           = mov.d	d15, a13
0x82,0x19           = mov	d9, #0x1
0x02,0x4f           = mov	d15, d4
0xd9,0xff,0xf4,0x42 = lea	a15, [a15]#0x2d34
0x89,0x40,0xc1,0x03 = cachei.wi	[a4+]#0x1
0x91,0x10,0x00,0x23 = movh.a	a2, #0x3001
0x6d,0xff,0x8b,0xfe = call	#-0x2ea
0x3c,0x1f           = j	#0x3e
0x6d,0x00,0xce,0x0d = call	#0x1b9c
0xda,0x7f           = mov	d15, #0x7f
0xd9,0xff,0x24,0x50 = lea	a15, [a15]#0x164
0xd9,0xff,0x7a,0x50 = lea	a15, [a15]#0x57a
0xbf,0x38,0xef,0xff = jlt.u	d8, #0x3, #-0x22
0x8b,0x87,0x01,0x10 = add	d1, d7, #0x18
0x3b,0x00,0x00,0x06 = mov	d0, #0x6000
0x91,0x10,0x00,0xa4 = movh.a	sp, #0x4001
0x37,0xf0,0x02,0x0e = insert	d0, d0, d15, #0x1c, #0x2
0xd9,0xff,0xc8,0x22 = lea	a15, [a15]#0x2c88
0x6d,0xb8,0x80,0x11 = call	#-0x8fdd00
0x15,0xd0,0xc0,0xeb = ldlcx	#0xd0003f80
0x4b,0x00,0x41,0x01 = itof	d0, d0
0xb4,0xc2           = st.h	[a12], d2
0x40,0xd5           = mov.aa	a5, a13
0x80,0x50           = mov.d	d0, a5
0x8f,0x34,0x40,0xf1 = or	d15, d4, #0x3
0x26,0xf3           = and	d3, d15
0xc6,0xf3           = xor	d3, d15
0x37,0x0f,0x6e,0xf1 = extr.u	d15, d15, #0x2, #0xe
0x02,0x48           = mov	d8, d4
0xd9,0xff,0x6c,0x10 = lea	a15, [a15]#0x46c
0xb0,0x14           = add.a	a4, #0x1
0x6f,0x00,0x1f,0x80 = jnz.t	d0, #0, #0x3e
0xd9,0xff,0x0c,0x40 = lea	a15, [a15]#0x10c
0x7b,0x00,0x00,0x11 = movh	d1, #0x1000
0x6d,0xff,0xe6,0xfc = call	#-0x634
0x6d,0xff,0x6e,0xfe = call	#-0x324
0x3b,0xf0,0x0f,0x00 = mov	d0, #0xff
0x6d,0xff,0x0c,0xfb = call	#-0x9e8
0x40,0x5c           = mov.aa	a12, a5
0x37,0x0f,0x62,0xf3 = extr.u	d15, d15, #0x6, #0x2
0xd9,0x22,0x04,0x00 = lea	a2, [a2]#0x4
0x40,0xc5           = mov.aa	a5, a12
0x53,0x41,0x20,0x10 = mul	d1, d1, #0x4
0x91,0x00,0x00,0x28 = movh.a	a2, #0x8000
0x82,0x17           = mov	d7, #0x1
0xd9,0xff,0x18,0x96 = lea	a15, [a15]#0x6258
0x20,0x08           = sub.a	sp, #0x8
0x8f,0x29,0x20,0xf0 = sha	d15, d9, #0x2
0x10,0x22           = addsc.a	a2, a2, d15, #0
0x60,0xc2           = mov.a	a2, d12
0xd9,0xff,0x30,0x96 = lea	a15, [a15]#0x6270
0x37,0xf0,0x02,0xf0 = insert	d15, d0, d15, #0, #0x2
0x6d,0xa0,0x80,0x11 = call	#-0xbfdd00
0x3b,0x00,0x00,0xf3 = mov	d15, #0x3000
0x6d,0x00,0x26,0x05 = call	#0xa4c
0xb7,0x0f,0x01,0xf1 = insert	d15, d15, #0, #0x2, #0x1
0x8f,0x24,0x00,0x00 = sh	d0, d4, #0x2
0x8b,0xff,0x01,0xf1 = rsub	d15, d15, #0x1f
0xd9,0xff,0x3c,0x96 = lea	a15, [a15]#0x627c
0x6d,0xff,0x0e,0xfb = call	#-0x9e4
0x6e,0x36           = jz	d15, #0x6c
0x9b,0xe1,0xcb,0x14 = addih	d1, d1, #0x4cbe
0xdc,0x0f           = ji	a15
0x53,0x4f,0x20,0xf0 = mul	d15, d15, #0x4
0xbf,0x38,0xce,0xff = jlt.u	d8, #0x3, #-0x64
0x49,0xf4,0x00,0x0a = lea	a4, [a15]#0
0x37,0xf0,0x03,0x00 = insert	d0, d0, d15, #0, #0x3
0x37,0x0f,0xe1,0xf2 = extr.u	d15, d15, #0x5, #0x1
0x37,0xf0,0x02,0x0f = insert	d0, d0, d15, #0x1e, #0x2
0x6d,0xff,0x1e,0xe9 = call	#-0x2dc4
0x8f,0x3f,0x00,0xd1 = and	d13, d15, #0x3
0x91,0x10,0x00,0xf5 = movh.a	a15, #0x5001
0x0f,0x91,0x10,0x10 = sha	d1, d1, d9
0x49,0xfc,0x14,0x0a = lea	a12, [a15]#0x14
0x6d,0xff,0xf4,0xfa = call	#-0xa18
0xd9,0xaa,0x40,0x89 = lea	sp, [sp]#-0x6a00
0x1d,0x00,0x03,0x00 = j	#0x6
0x91,0x10,0x00,0xa5 = movh.a	sp, #0x5001
0x6d,0x00,0xc3,0x06 = call	#0xd86
0x0f,0x0f,0x10,0xf0 = sha	d15, d15, d0
0xd9,0x99,0x00,0x00 = lea	a9, [a9]#0
0x06,0x21           = sh	d1, #0x2
0x4b,0x04,0x11,0x22 = div.u	e2, d4, d0
0x6d,0xff,0xd2,0xe7 = call	#-0x305c
0x20,0x58           = sub.a	sp, #0x58
0x7f,0xf9,0x04,0x80 = jge.u	d9, d15, #0x8
0xee,0x07           = jnz	d15, #0xe
0x49,0xcf,0x38,0x0a = lea	a15, [a12]#0x38
0xd9,0xff,0x74,0x30 = lea	a15, [a15]#0x4f4
0x4b,0x10,0x41,0x00 = mul.f	d0, d0, d1
0xbf,0x81,0x03,0x80 = jlt.u	d1, #0x8, #0x6
0x7f,0xf9,0x0b,0x80 = jge.u	d9, d15, #0x16
0xd9,0xff,0x80,0xc9 = lea	a15, [a15]#-0x6500
0x6d,0xd0,0xf4,0x11 = call	#-0x5fdc18
0xb7,0x0f,0x02,0xf0 = insert	d15, d15, #0, #0, #0x2
0xd9,0x44,0x08,0x60 = lea	a4, [a4]#0x188
0x82,0x26           = mov	d6, #0x2
0x37,0x01,0x70,0x20 = extr.u	d2, d1, #0, #0x10
0xdc,0x0b           = ji	a11
0xd9,0xff,0xc0,0x05 = lea	a15, [a15]#0x5c00
0x8f,0x00,0x01,0x00 = sh	d0, d0, #0x10
0x3c,0x07           = j	#0xe
0xc2,0x18           = add	d8, #0x1
0x6d,0xff,0xce,0xfb = call	#-0x864
0x6d,0x00,0x61,0x01 = call	#0x2c2
0x6d,0x00,0xb7,0x00 = call	#0x16e
0x8f,0x3c,0x00,0x41 = and	d4, d12, #0x3
0xc6,0xf0           = xor	d0, d15
0x6d,0xff,0x04,0xfa = call	#-0xbf8
0xb7,0x0f,0x08,0xf0 = insert	d15, d15, #0, #0, #0x8
0x91,0x40,0x88,0x4f = movh.a	a4, #0xf884
0x6d,0x00,0x1b,0x0e = call	#0x1c36
0xb7,0x0f,0x01,0xf0 = insert	d15, d15, #0, #0, #0x1
0x7e,0x09           = jne	d15, d0, #0x12
0x8f,0x24,0x00,0xf0 = sh	d15, d4, #0x2
0x6d,0xff,0x8b,0xff = call	#-0xea
0x49,0x33,0x14,0x8a = lea	a3, [a3]#-0x1ec
0xc6,0x10           = xor	d0, d1
0x37,0x10,0x01,0x01 = insert	d0, d0, d1, #0x2, #0x1
0x4b,0x0f,0x51,0xf0 = div.f	d15, d15, d0
0x4b,0x01,0x51,0x00 = div.f	d0, d1, d0
0x1e,0x17           = jeq	d15, #0x1, #0xe
0x6d,0xff,0x80,0xff = call	#-0x100
0xbb,0xf0,0xff,0xff = mov.u	d15, #0xffff
0x3e,0x4a           = jeq	d15, d4, #0x14
0x3b,0x00,0x40,0x00 = mov	d0, #0x400
0x37,0xf0,0x05,0xf2 = insert	d15, d0, d15, #0x4, #0x5
0x91,0x00,0x03,0xf8 = movh.a	a15, #0x8030
0x8f,0x21,0x20,0xf0 = sha	d15, d1, #0x2
0x7f,0xf9,0x0d,0x80 = jge.u	d9, d15, #0x1a
0x76,0x91           = jz	d9, #0x2
0x02,0x92           = mov	d2, d9
0x3f,0x0f,0xfd,0xff = jlt.u	d15, d0, #-0x6
0x6d,0xe8,0x17,0x00 = call	#-0x2fffd2
0x82,0x08           = mov	d8, #0
0x6d,0xff,0x05,0xfc = call	#-0x7f6
0xd9,0xff,0x08,0x23 = lea	a15, [a15]#0x3088
0x37,0x00,0xe1,0x00 = extr.u	d0, d0, #0x1, #0x1
0x37,0x0f,0xe1,0xf0 = extr.u	d15, d15, #0x1, #0x1
0x76,0xcf           = jz	d12, #0x1e
0x82,0x01           = mov	d1, #0
0xa2,0xdc           = sub	d12, d13
0xd9,0x44,0x18,0x60 = lea	a4, [a4]#0x198
0x9b,0x81,0xb9,0x14 = addih	d1, d1, #0x4b98
0xb7,0x0f,0x01,0xfc = insert	d15, d15, #0, #0x18, #0x1
0x37,0x0f,0x05,0xf8 = insert	d15, d15, d0, #0x10, #0x5
0x2d,0x0f,0x20,0x00 = jli	a15
0x53,0x44,0x20,0xf0 = mul	d15, d4, #0x4
0x91,0x40,0x00,0xa6 = movh.a	sp, #0x6004
0x3e,0x4e           = jeq	d15, d4, #0x1c
0xd9,0xff,0x00,0x06 = lea	a15, [a15]#0x6000
0x6d,0x00,0x53,0x00 = call	#0xa6
0xb7,0x0f,0x0c,0xfa = insert	d15, d15, #0, #0x14, #0xc
0xa0,0x04           = mov.a	a4, #0
0x6d,0xff,0xed,0xf7 = call	#-0x1026
0xd9,0xff,0x0c,0x96 = lea	a15, [a15]#0x624c
0x3c,0x21           = j	#0x42
0x37,0xf0,0x02,0xf2 = insert	d15, d0, d15, #0x4, #0x2
0xdf,0x0c,0xe0,0x7f = jeq	d12, #0, #-0x40
0xbb,0xf0,0xff,0x2f = mov.u	d2, #0xffff
0x49,0x42,0x00,0x0a = lea	a2, [a4]#0
0xd9,0xff,0x70,0x20 = lea	a15, [a15]#0x4b0
0x8f,0xec,0x1f,0xf0 = sh	d15, d12, #-0x2
0xd9,0x44,0x28,0xa6 = lea	a4, [a4]#0x62a8
0x7f,0xf9,0x03,0x80 = jge.u	d9, d15, #0x6
0x91,0x20,0x88,0x4f = movh.a	a4, #0xf882
0xbb,0x00,0xc2,0x2b = mov.u	d2, #0xbc20
0xa0,0x15           = mov.a	a5, #0x1
0x6d,0xff,0xfc,0xfe = call	#-0x208
0x6d,0xe8,0x90,0x0f = call	#-0x2fe0e0
0x6f,0x1f,0xfa,0xff = jnz.t	d15, #0x1, #-0xc
0x49,0x33,0x08,0x8a = lea	a3, [a3]#-0x1f8
0xda,0x10           = mov	d15, #0x10
0x6f,0x20,0xf2,0x7f = jz.t	d0, #0x2, #-0x1c
0xd9,0x2e,0x40,0x00 = lea	a14, [a2]#0x400
0x26,0xf0           = and	d0, d15
0xb7,0x01,0x02,0x20 = insert	d2, d1, #0, #0, #0x2
0x6d,0xff,0x99,0xfb = call	#-0x8ce
0x3e,0x12           = jeq	d15, d1, #0x4
0x26,0x02           = and	d2, d0
0xdf,0x1f,0x70,0x80 = jne	d15, #0x1, #0xe0
0x06,0x1f           = sh	d15, #0x1
0x3e,0x56           = jeq	d15, d5, #0xc
0xda,0x1f           = mov	d15, #0x1f
0xc2,0xf1           = add	d1, #-0x1
0x49,0xff,0x00,0x1a = lea	a15, [a15]#0x40
0x4b,0xf1,0x41,0x10 = mul.f	d1, d1, d15
0x6d,0xff,0x67,0xfc = call	#-0x732
0x8f,0x31,0x40,0xf1 = or	d15, d1, #0x3
0x96,0x03           = or	d15, #0x3
0x37,0x0f,0x04,0xf2 = insert	d15, d15, d0, #0x4, #0x4
0x4b,0x0f,0x71,0x41 = ftouz	d4, d15
0x6d,0xff,0x01,0xfb = call	#-0x9fe
0xc2,0x12           = add	d2, #0x1
0x37,0x01,0x10,0x10 = insert	d1, d1, d0, #0, #0x10
0x53,0x4a,0x20,0x20 = mul	d2, d10, #0x4
0xe2,0x10           = mul	d0, d1
0x7f,0x20,0x04,0x80 = jge.u	d0, d2, #0x8
0x80,0xd0           = mov.d	d0, a13
0x37,0x09,0x68,0x90 = extr.u	d9, d9, #0, #0x8
0x02,0xf4           = mov	d4, d15
0x6f,0x20,0xf8,0x7f = jz.t	d0, #0x2, #-0x10
0x6d,0x00,0x8a,0x00 = call	#0x114
0x3c,0x17           = j	#0x2e
0x3f,0xf0,0x05,0x80 = jlt.u	d0, d15, #0xa
0x3b,0x00,0x10,0xf0 = mov	d15, #0x100
0xda,0x0c           = mov	d15, #0xc
0x6d,0x00,0x4b,0x00 = call	#0x96
0x8b,0xf0,0x2f,0x03 = min.u	d0, d0, #0xff
0xbb,0x00,0x68,0xf9 = mov.u	d15, #0x9680
0x3b,0xb0,0x7f,0x00 = mov	d0, #0x7fb
0xfe,0x04           = jne	d15, d0, #0x28
0x6d,0xff,0x45,0xfc = call	#-0x776
0xbb,0xd0,0xcc,0x0c = mov.u	d0, #0xcccd
0x6d,0x00,0x5d,0x00 = call	#0xba
0x82,0x12           = mov	d2, #0x1
0x37,0x0f,0x01,0xff = insert	d15, d15, d0, #0x1e, #0x1
0xbf,0x30,0xe1,0xff = jlt.u	d0, #0x3, #-0x3e
0x4b,0xbf,0x41,0xf0 = mul.f	d15, d15, d11
0xbf,0x20,0xef,0xff = jlt.u	d0, #0x2, #-0x22
0x3c,0x1a           = j	#0x34
0x53,0x69,0x20,0xf0 = mul	d15, d9, #0x6
0x01,0xcd,0x00,0xc6 = addsc.a	a12, a12, d13, #0
0x6d,0x00,0x1a,0x09 = call	#0x1234
0x09,0xc0,0xca,0x28 = ld.hu	d0, [a12]#0x8a
0x7f,0xf9,0x0f,0x80 = jge.u	d9, d15, #0x1e
0x6d,0xff,0x62,0xfb = call	#-0x93c
0xb7,0x1f,0x81,0x1b = insert	d1, d15, #0x1, #0x17, #0x1
0xd9,0xff,0x00,0x00 = lea	a15, [a15]#0
0xbf,0xc9,0x06,0x80 = jlt.u	d9, #0xc, #0xc
0xda,0x02           = mov	d15, #0x2
0x40,0x5f           = mov.aa	a15, a5
0x91,0x20,0x00,0x5f = movh.a	a5, #0xf002
0x37,0x0f,0x61,0xf2 = extr.u	d15, d15, #0x4, #0x1
0x91,0x00,0x0c,0xfa = movh.a	a15, #0xa0c0
0x53,0xc8,0x21,0xf0 = mul	d15, d8, #0x1c
0x37,0x0f,0xe1,0xf3 = extr.u	d15, d15, #0x7, #0x1
0xda,0x0f           = mov	d15, #0xf
0x6e,0x04           = jz	d15, #0x8
0x0f,0xf1,0x00,0x10 = sh	d1, d1, d15
0x6d,0xff,0x7b,0xfc = call	#-0x70a
0x9b,0xb0,0xbf,0x04 = addih	d0, d0, #0x4bfb
0x09,0xff,0xca,0x28 = ld.hu	d15, [a15]#0x8a
0xfc,0x5e           = loop	a5, #-0x4
0xda,0x03           = mov	d15, #0x3
0x20,0x28           = sub.a	sp, #0x28
0x82,0x16           = mov	d6, #0x1
0xd9,0xff,0x20,0xe0 = lea	a15, [a15]#0x3a0
0xee,0x04           = jnz	d15, #0x8
0x4b,0xf0,0x11,0x22 = div.u	e2, d0, d15
0x6d,0x00,0xf9,0x07 = call	#0xff2
0x16,0x03           = and	d15, #0x3
0x4b,0xf2,0x51,0xf0 = div.f	d15, d2, d15
0x6d,0xff,0xca,0xfc = call	#-0x66c
0x82,0x30           = mov	d0, #0x3
0x82,0xff           = mov	d15, #-0x1
0x8f,0x3c,0x00,0x01 = and	d0, d12, #0x3
0x3e,0x1b           = jeq	d15, d1, #0x16
0x32,0x5f           = rsub	d15
0x82,0xf2           = mov	d2, #-0x1
0x40,0xd2           = mov.aa	a2, a13
0xd9,0xff,0x80,0xc5 = lea	a15, [a15]#0x5b00
0x91,0x00,0x00,0x10 = movh.a	a1, #0
0x3e,0x47           = jeq	d15, d4, #0xe
0xdf,0x10,0x2b,0x80 = jne	d0, #0x1, #0x56
0xde,0x28           = jne	d15, #0x2, #0x30
0x37,0x0f,0x68,0x40 = extr.u	d4, d15, #0, #0x8
0x8f,0xff,0x83,0xf1 = xor	d15, d15, #0x3f
0x06,0x3f           = sh	d15, #0x3
0x82,0x14           = mov	d4, #0x1
0x3b,0x90,0xd0,0x33 = mov	d3, #0x3d09
0x02,0x94           = mov	d4, d9
0x6d,0xff,0x9b,0xfc = call	#-0x6ca
0x53,0xc2,0x20,0xf0 = mul	d15, d2, #0xc
0x7b,0xc0,0xff,0x0f = movh	d0, #0xfffc
0x6f,0x1f,0x12,0x00 = jz.t	d15, #0x1, #0x24
0xd9,0xff,0x3c,0x50 = lea	a15, [a15]#0x17c
0xd9,0xff,0x78,0x40 = lea	a15, [a15]#0x538
0x40,0xf4           = mov.aa	a4, a15
0x4e,0x33           = jgtz	d3, #0x6
0xdf,0x1f,0x29,0x80 = jne	d15, #0x1, #0x52
0xb7,0x0f,0x81,0xf1 = insert	d15, d15, #0, #0x3, #0x1
0x3e,0x46           = jeq	d15, d4, #0xc
0x37,0x01,0x81,0x01 = insert	d0, d1, d0, #0x3, #0x1
0xc2,0xf4           = add	d4, #-0x1
0x91,0x30,0x00,0x2f = movh.a	a2, #0xf003
0x3f,0x02,0x08,0x80 = jlt.u	d2, d0, #0x10
0x53,0x80,0x20,0xf0 = mul	d15, d0, #0x8
0x6d,0xff,0x53,0xfc = call	#-0x75a
0xd9,0xff,0xc4,0xc2 = lea	a15, [a15]#0x2f04
0x96,0x08           = or	d15, #0x8
0x37,0x0f,0x62,0xf2 = extr.u	d15, d15, #0x4, #0x2
0x10,0xf4           = addsc.a	a4, a15, d15, #0
0x4b,0xf2,0x51,0x20 = div.f	d2, d2, d15
0xda,0x96           = mov	d15, #0x96
0x5e,0x23           = jne	d15, #0x2, #0x6
0x82,0x04           = mov	d4, #0
0x16,0x0f           = and	d15, #0xf
0xd9,0x22,0x00,0x00 = lea	a2, [a2]#0
0x3e,0x66           = jeq	d15, d6, #0xc
0x9b,0xe2,0xcb,0x24 = addih	d2, d2, #0x4cbe
0x4e,0x03           = jgtz	d0, #0x6
0x1d,0xff,0x77,0xff = j	#-0x112
0xbf,0x21,0xcd,0xff = jlt.u	d1, #0x2, #-0x66
0x3b,0xf0,0x00,0x30 = mov	d3, #0xf
0x16,0x5f           = and	d15, #0x5f
0x09,0xff,0xc6,0x08 = ld.hu	d15, [a15]#0x6
0x8b,0xf2,0x00,0x00 = add	d0, d2, #0xf
0x6d,0xff,0xdf,0xfa = call	#-0xa42
0xf6,0x06           = jnz	d0, #0xc
0x02,0x0c           = mov	d12, d0
0x91,0x80,0x88,0x4f = movh.a	a4, #0xf888
0xd9,0xff,0x24,0x96 = lea	a15, [a15]#0x6264
0x37,0x0f,0x82,0xf6 = insert	d15, d15, d0, #0xd, #0x2
0x6d,0xff,0xae,0xf8 = call	#-0xea4
0x4b,0xf0,0x41,0xf0 = mul.f	d15, d0, d15
0x82,0x24           = mov	d4, #0x2
0x06,0x24           = sh	d4, #0x2
0xff,0x8f,0x1a,0x80 = jge.u	d15, #0x8, #0x34
0x6d,0xff,0x01,0xfc = call	#-0x7fe
0x8f,0x3c,0x00,0xf1 = and	d15, d12, #0x3
0x82,0x06           = mov	d6, #0
0x02,0x90           = mov	d0, d9
0x4b,0x0f,0x71,0x01 = ftouz	d0, d15
0x37,0x0f,0x62,0xf6 = extr.u	d15, d15, #0xc, #0x2
0x49,0xcf,0x28,0x0a = lea	a15, [a12]#0x28
0x01,0x28,0x00,0x26 = addsc.a	a2, a2, d8, #0
0x06,0xaf           = sh	d15, #-0x6
0x86,0x24           = sha	d4, #0x2
0xb7,0x3f,0x08,0xf0 = insert	d15, d15, #0x3, #0, #0x8
0x9b,0xb1,0xa5,0x14 = addih	d1, d1, #0x4a5b
0x6d,0xff,0x75,0xfc = call	#-0x716
0x3c,0x00           = j	#0x0
0x86,0x21           = sha	d1, #0x2
0xbe,0x60           = jeq	d15, d6, #0x20
0x6d,0xff,0xc5,0xff = call	#-0x76
0xdf,0x10,0xee,0x7f = jeq	d0, #0x1, #-0x24
0xfc,0x29           = loop	a2, #-0xe
0xa6,0xf0           = or	d0, d15
0x8f,0x2a,0x20,0xf0 = sha	d15, d10, #0x2
0xda,0x20           = mov	d15, #0x20
0x26,0x30           = and	d0, d3
0xc6,0x3f           = xor	d15, d3
0x37,0xf3,0x08,0x38 = insert	d3, d3, d15, #0x10, #0x8
0x4b,0x08,0x61,0x01 = utof	d0, d8
0x37,0x0f,0xe2,0xf0 = extr.u	d15, d15, #0x1, #0x2
0x0f,0xf3,0x00,0x30 = sh	d3, d3, d15
0x53,0xcf,0x20,0x10 = mul	d1, d15, #0xc
0x7b,0xa0,0x47,0x04 = movh	d0, #0x447a
0x5f,0x2f,0xf4,0xff = jne	d15, d2, #-0x18
0x4b,0xf0,0x11,0x42 = div.u	e4, d0, d15
0xb7,0x2f,0x02,0xf5 = insert	d15, d15, #0x2, #0xa, #0x2
0x6e,0x03           = jz	d15, #0x6
0x5f,0x6f,0x23,0x00 = jeq	d15, d6, #0x46
0x3f,0x10,0x97,0xff = jlt.u	d0, d1, #-0xd2
0x37,0x0f,0xe7,0xf0 = extr.u	d15, d15, #0x1, #0x7
0x37,0xf0,0x03,0x0c = insert	d0, d0, d15, #0x18, #0x3
0xa6,0x5f           = or	d15, d5
0x91,0x10,0x88,0xff = movh.a	a15, #0xf881
0xda,0x15           = mov	d15, #0x15
0x53,0x20,0x20,0xf0 = mul	d15, d0, #0x2
0x6d,0xff,0x43,0xfd = call	#-0x57a
0x3c,0xd9           = j	#-0x4e
0xb7,0x5f,0x08,0xf0 = insert	d15, d15, #0x5, #0, #0x8
0x8f,0x28,0x00,0xf0 = sh	d15, d8, #0x2
0x6d,0xff,0x4b,0xfb = call	#-0x96a
0xbb,0x00,0x68,0x19 = mov.u	d1, #0x9680
0x91,0x10,0x00,0x24 = movh.a	a2, #0x4001
0xfc,0x2e           = loop	a2, #-0x4
0xfc,0x2f           = loop	a2, #-0x2
0xd9,0xaa,0x40,0x85 = lea	sp, [sp]#0x5600
0x6d,0xff,0x32,0xff = call	#-0x19c
0x91,0x10,0x00,0xa1 = movh.a	sp, #0x1001
0x02,0xf1           = mov	d1, d15
0xe2,0xf0           = mul	d0, d15
0x82,0x05           = mov	d5, #0
0x7e,0x0d           = jne	d15, d0, #0x1a
0x37,0xf0,0x01,0xf0 = insert	d15, d0, d15, #0, #0x1
0x37,0x0f,0x81,0xfb = insert	d15, d15, d0, #0x17, #0x1
0xdf,0x1f,0xfb,0x7f = jeq	d15, #0x1, #-0xa
0x15,0xd0,0xc0,0xff = lducx	#0xd0003fc0
0x6d,0xff,0xb8,0xf2 = call	#-0x1a90
0xdf,0x1f,0x54,0x80 = jne	d15, #0x1, #0xa8
0x7e,0x93           = jne	d15, d9, #0x6
0x37,0x0f,0x65,0xf2 = extr.u	d15, d15, #0x4, #0x5
0x6d,0xff,0x68,0xfb = call	#-0x930
0x91,0x50,0x02,0xff = movh.a	a15, #0xf025
0x3c,0x16           = j	#0x2c
0x6f,0x10,0xf2,0x7f = jz.t	d0, #0x1, #-0x1c
0xdf,0x10,0xea,0x7f = jeq	d0, #0x1, #-0x2c
0xdf,0x10,0xf6,0x7f = jeq	d0, #0x1, #-0x14
0x91,0x00,0x00,0x47 = movh.a	a4, #0x7000
0x6d,0xff,0x83,0xfc = call	#-0x6fa
0xdf,0x0c,0x86,0x7f = jeq	d12, #0, #-0xf4
0x3c,0xc4           = j	#-0x78
0xa2,0x8f           = sub	d15, d8
0x02,0xf2           = mov	d2, d15
0xd9,0xff,0xa4,0x72 = lea	a15, [a15]#0x29e4
0xd9,0x22,0xc0,0x07 = lea	a2, [a2]#0x7c00
0x82,0x00           = mov	d0, #0
0x37,0x00,0x68,0x40 = extr.u	d4, d0, #0, #0x8
0x6d,0xff,0x5b,0xfc = call	#-0x74a
0x37,0x00,0xe7,0x00 = extr.u	d0, d0, #0x1, #0x7
0xdf,0x12,0x03,0x80 = jne	d2, #0x1, #0x6
0x91,0x10,0x00,0xa3 = movh.a	sp, #0x3001
0xc2,0x31           = add	d1, #0x3
0x6d,0xff,0x2f,0xf8 = call	#-0xfa2
0x37,0xf1,0x08,0xf0 = insert	d15, d1, d15, #0, #0x8
0x3b,0x00,0x98,0xf0 = mov	d15, #0x980
0x82,0x09           = mov	d9, #0
0xbe,0x10           = jeq	d15, d1, #0x20
0xda,0x1d           = mov	d15, #0x1d
0x3f,0x10,0xee,0xff = jlt.u	d0, d1, #-0x24
0x82,0x11           = mov	d1, #0x1
0x8f,0x3f,0x00,0x01 = and	d0, d15, #0x3
0x40,0xe4           = mov.aa	a4, a14
0xc5,0x06,0x14,0x00 = lea	a6, #0x14
0x96,0x80           = or	d15, #0x80
0x91,0x10,0x00,0x21 = movh.a	a2, #0x1001
0x26,0x0f           = and	d15, d0
0x0f,0x31,0x10,0x10 = sha	d1, d1, d3
0x91,0x30,0x00,0x3f = movh.a	a3, #0xf003
0xd9,0xff,0x14,0x23 = lea	a15, [a15]#0x3094
0x6d,0xe8,0x80,0x11 = call	#-0x2fdd00
0x6e,0x1d           = jz	d15, #0x3a
0x7f,0xf9,0x02,0x80 = jge.u	d9, d15, #0x4
0xd9,0xff,0xe8,0xc2 = lea	a15, [a15]#0x2f28
0x37,0x5f,0x04,0xf4 = insert	d15, d15, d5, #0x8, #0x4
0x4b,0xf2,0x41,0xf0 = mul.f	d15, d2, d15
0xd9,0x22,0x28,0xa6 = lea	a2, [a2]#0x62a8
0xc2,0x81           = add	d1, #-0x8
0xbb,0x00,0xc2,0xfb = mov.u	d15, #0xbc20
0x37,0x1f,0x02,0xf0 = insert	d15, d15, d1, #0, #0x2
0x0f,0xf1,0x10,0x10 = sha	d1, d1, d15
0x6d,0x00,0xf0,0x04 = call	#0x9e0
0x0f,0x3f,0x00,0xf0 = sh	d15, d15, d3
0x02,0xd4           = mov	d4, d13
0x40,0x4f           = mov.aa	a15, a4
0x9b,0x1f,0x8d,0xf3 = addih	d15, d15, #0x38d1
0x7b,0x00,0xf0,0x13 = movh	d1, #0x3f00
0x7b,0x00,0x00,0x14 = movh	d1, #0x4000
0x6d,0xff,0xee,0xe8 = call	#-0x2e24
0x06,0x62           = sh	d2, #0x6
0x4b,0xf2,0x51,0xa0 = div.f	d10, d2, d15
0x49,0xf2,0x1c,0x0a = lea	a2, [a15]#0x1c
0x8f,0x24,0x20,0xf0 = sha	d15, d4, #0x2
0x40,0xd4           = mov.aa	a4, a13
0x10,0xd2           = addsc.a	a2, a13, d15, #0
0x6d,0x00,0x6d,0x03 = call	#0x6da
0xb7,0x1f,0x08,0xf0 = insert	d15, d15, #0x1, #0, #0x8
0xd9,0x22,0xc0,0x0b = lea	a2, [a2]#-0x4400
0x9a,0x81           = add	d15, d1, #-0x8
0x91,0x00,0x00,0xf8 = movh.a	a15, #0x8000
0x37,0x0f,0x83,0xf1 = insert	d15, d15, d0, #0x3, #0x3
0x7e,0x05           = jne	d15, d0, #0xa
0x6d,0xa0,0xf4,0x11 = call	#-0xbfdc18
0x49,0xff,0x0c,0x0a = lea	a15, [a15]#0xc
0xb7,0x6f,0x08,0xf0 = insert	d15, d15, #0x6, #0, #0x8
0x10,0xe4           = addsc.a	a4, a14, d15, #0
0x7f,0xf0,0x19,0x00 = jge	d0, d15, #0x32
0x7e,0x91           = jne	d15, d9, #0x2
0x0f,0x0f,0x00,0xf0 = sh	d15, d15, d0
0x6e,0xef           = jz	d15, #-0x22
0x3c,0x05           = j	#0xa
0x6d,0x00,0x25,0x0d = call	#0x1a4a
0x42,0x01           = add	d1, d0
0xae,0x17           = jnz.t	d15, #0x1, #0xe
0x91,0x40,0x00,0x27 = movh.a	a2, #0x7004
0x3b,0x00,0x40,0xf0 = mov	d15, #0x400
0x09,0xa0,0xc4,0x08 = ld.hu	d0, [sp]#0x4
0x6f,0x0f,0xfc,0x7f = jz.t	d15, #0, #-0x8
0x02,0x82           = mov	d2, d8
0x37,0x0f,0x68,0xf0 = extr.u	d15, d15, #0, #0x8
0x1d,0x00,0x02,0x00 = j	#0x4
0xa2,0x10           = sub	d0, d1
0x37,0xf0,0x01,0xf3 = insert	d15, d0, d15, #0x6, #0x1
0x91,0x20,0x00,0x30 = movh.a	a3, #0x2
0x6d,0x00,0xd8,0x0c = call	#0x19b0
0x6d,0xd0,0x80,0x11 = call	#-0x5fdd00
0xae,0x75           = jnz.t	d15, #0x7, #0xa
0x91,0x50,0x02,0x2f = movh.a	a2, #0xf025
0x3c,0x02           = j	#0x4
0xda,0x14           = mov	d15, #0x14
0x82,0x02           = mov	d2, #0
0x82,0x07           = mov	d7, #0
0xbc,0xf1           = jz.a	a15, #0x2
0x6d,0xff,0xe0,0xfb = call	#-0x840
0x37,0x00,0x70,0x08 = extr.u	d0, d0, #0x10, #0x10
0x82,0x15           = mov	d5, #0x1
0xd9,0xff,0xec,0xe2 = lea	a15, [a15]#0x2fac
0xbe,0x40           = jeq	d15, d4, #0x20
0x3c,0x1b           = j	#0x36
0x37,0xf0,0x02,0x0a = insert	d0, d0, d15, #0x14, #0x2
0x8f,0xff,0x83,0x41 = xor	d4, d15, #0x3f
0x3e,0x16           = jeq	d15, d1, #0xc
0x6e,0x09           = jz	d15, #0x12
0x3f,0xf2,0xf3,0x7f = jlt	d2, d15, #-0x1a
0x6d,0x00,0x04,0x00 = call	#0x8
0xa6,0x10           = or	d0, d1
0xda,0x40           = mov	d15, #0x40
0x6e,0x1a           = jz	d15, #0x34
0x91,0x00,0x0f,0xfa = movh.a	a15, #0xa0f0
0x6d,0xff,0xc5,0xfe = call	#-0x276
0x9b,0xc0,0xfc,0x03 = addih	d0, d0, #0x3fcc
0x37,0x0f,0x02,0xf3 = insert	d15, d15, d0, #0x6, #0x2
0xdf,0x10,0x0a,0x80 = jne	d0, #0x1, #0x14
0x8f,0x00,0x21,0x00 = sha	d0, d0, #0x10
0xfd,0xf0,0xed,0x7f = loop	a15, #-0x26
0x7b,0x00,0x00,0xf4 = movh	d15, #0x4000
0x37,0x00,0x62,0xf2 = extr.u	d15, d0, #0x4, #0x2
0x3f,0x0f,0x04,0x80 = jlt.u	d15, d0, #0x8
0x3c,0x11           = j	#0x22
0x01,0xdd,0x00,0xd6 = addsc.a	a13, a13, d13, #0
0x82,0x10           = mov	d0, #0x1
0xee,0x02           = jnz	d15, #0x4
0x82,0x27           = mov	d7, #0x2
0xfe,0xdb           = jne	d15, d13, #0x36
0x37,0x04,0x68,0xf0 = extr.u	d15, d4, #0, #0x8
0x3e,0x04           = jeq	d15, d0, #0x8
0x06,0xf4           = sh	d4, #-0x1
0x37,0xf0,0x01,0x00 = insert	d0, d0, d15, #0, #0x1
0xbf,0xc9,0x07,0x80 = jlt.u	d9, #0xc, #0xe
0x3c,0x0e           = j	#0x1c
0x7b,0x00,0x20,0x04 = movh	d0, #0x4200
0x30,0x43           = add.a	a3, a4
0x91,0x00,0x09,0xfa = movh.a	a15, #0xa090
0x91,0x10,0x00,0xf3 = movh.a	a15, #0x3001
0x3c,0x20           = j	#0x40
0x6d,0xe8,0xe1,0x0e = call	#-0x2fe23e
0x6d,0xff,0xaa,0xf9 = call	#-0xcac
0xb7,0x7f,0x03,0xfe = insert	d15, d15, #0x7, #0x1c, #0x3
0xb7,0x00,0x81,0x01 = insert	d0, d0, #0, #0x3, #0x1
0x0f,0x10,0x10,0x00 = sha	d0, d0, d1
0xa2,0x0f           = sub	d15, d0
0xc6,0xf1           = xor	d1, d15
0x8f,0x3f,0x00,0x10 = sh	d1, d15, #0x3
0x49,0xcf,0x30,0x0a = lea	a15, [a12]#0x30
0x26,0x10           = and	d0, d1
0x5e,0x1b           = jne	d15, #0x1, #0x16
0xc6,0x2f           = xor	d15, d2
0x53,0x01,0x21,0xf0 = mul	d15, d1, #0x10
0x91,0x40,0x00,0xf6 = movh.a	a15, #0x6004
0xbf,0xc9,0x05,0x80 = jlt.u	d9, #0xc, #0xa
0x8f,0xff,0x83,0xa1 = xor	d10, d15, #0x3f
0x91,0x40,0x00,0x26 = movh.a	a2, #0x6004
0x37,0xf3,0x08,0x30 = insert	d3, d3, d15, #0, #0x8
0x4b,0xf0,0x51,0x20 = div.f	d2, d0, d15
0x82,0x0b           = mov	d11, #0
0x42,0xf0           = add	d0, d15
0xd9,0xff,0x30,0x03 = lea	a15, [a15]#0x3030
0x6d,0x00,0xbe,0x02 = call	#0x57c
0xb7,0x0f,0x1c,0xf0 = insert	d15, d15, #0, #0, #0x1c
0xa6,0x64           = or	d4, d6
0x37,0x4f,0x9f,0xf0 = insert	d15, d15, d4, #0x1, #0x1f
0x6d,0xe8,0xf4,0x11 = call	#-0x2fdc18
0x4b,0x30,0x11,0x42 = div.u	e4, d0, d3
0xd9,0x44,0x3c,0x50 = lea	a4, [a4]#0x17c
0xc2,0xff           = add	d15, #-0x1
0x26,0xf1           = and	d1, d15
0x91,0x00,0x0f,0xf8 = movh.a	a15, #0x80f0
0x91,0x30,0x00,0x4f = movh.a	a4, #0xf003
0x3b,0x00,0x02,0x60 = mov	d6, #0x20
0x3f,0xf9,0x65,0xff = jlt.u	d9, d15, #-0x136
0x3e,0x58           = jeq	d15, d5, #0x10
0x10,0xaf           = addsc.a	a15, sp, d15, #0
0xdf,0x0c,0xd3,0x7f = jeq	d12, #0, #-0x5a
0x53,0x00,0x21,0xf0 = mul	d15, d0, #0x10
0x3e,0x4b           = jeq	d15, d4, #0x16
0x3f,0xf0,0xfd,0xff = jlt.u	d0, d15, #-0x6
0xdf,0x1f,0xfe,0x7f = jeq	d15, #0x1, #-0x4
0x6d,0xff,0x6f,0xfc = call	#-0x722
0xfc,0x4e           = loop	a4, #-0x4
0x8b,0x5f,0x20,0xf3 = min.u	d15, d15, #0x5
0x01,0xf0,0x00,0xf6 = addsc.a	a15, a15, d0, #0
0x8f,0x3f,0x00,0x30 = sh	d3, d15, #0x3
0x3c,0x34           = j	#0x68
0x90,0xdd           = addsc.a	a13, a13, d15, #0x2
0x6d,0xff,0xa6,0xff = call	#-0xb4
0x37,0x4f,0x04,0xf8 = insert	d15, d15, d4, #0x10, #0x4
0x37,0x00,0x68,0x00 = extr.u	d0, d0, #0, #0x8
0x10,0xcc           = addsc.a	a12, a12, d15, #0
0xee,0x06           = jnz	d15, #0xc
0x6d,0xff,0x00,0xfb = call	#-0xa00
0x10,0xcf           = addsc.a	a15, a12, d15, #0
0x7f,0x0f,0x07,0x80 = jge.u	d15, d0, #0xe
0xd9,0xff,0x08,0xa6 = lea	a15, [a15]#0x6288
0xbe,0x65           = jeq	d15, d6, #0x2a
0x3e,0x5a           = jeq	d15, d5, #0x14
0x26,0x2f           = and	d15, d2
0x92,0x10           = add	d0, d15, #0x1
0x26,0x3f           = and	d15, d3
0x6d,0xff,0x8b,0xfb = call	#-0x8ea
0x6d,0x00,0xf1,0x00 = call	#0x1e2
0xdf,0x04,0x7c,0x7f = jeq	d4, #0, #-0x108
0x8f,0x4f,0x1f,0x10 = sh	d1, d15, #-0xc
0xd9,0x88,0x00,0x00 = lea	a8, [a8]#0
0xd7,0x10,0x21,0x0f = imask	e0, #0x1, d15, #0x1
0x8f,0x23,0x20,0xf0 = sha	d15, d3, #0x2
0x6b,0x0f,0x61,0x41 = madd.f	d4, d1, d15, d0
0xc2,0x1f           = add	d15, #0x1
0x6d,0xff,0xb6,0xfa = call	#-0xa94
0xc5,0x02,0x3f,0x10 = lea	a2, #0x7f
0x80,0x20           = mov.d	d0, a2
0xbe,0x9c           = jeq	d15, d9, #0x38
0x6e,0xe8           = jz	d15, #-0x30
0x91,0x10,0x00,0xf4 = movh.a	a15, #0x4001
0xe2,0x9f           = mul	d15, d9
0x3c,0x1e           = j	#0x3c
0xb7,0x04,0x08,0xfc = insert	d15, d4, #0, #0x18, #0x8
0x6e,0x07           = jz	d15, #0xe
0xbb,0x00,0x52,0x0c = mov.u	d0, #0xc520
0xa6,0x20           = or	d0, d2
0x3c,0x1d           = j	#0x3a
0x6d,0x00,0x2d,0x07 = call	#0xe5a
0x8f,0x0f,0x1f,0x00 = sh	d0, d15, #-0x10
0x8b,0x09,0x01,0x00 = add	d0, d9, #0x10
0xc2,0xfc           = add	d12, #-0x1
0x3b,0xf0,0x49,0x02 = mov	d0, #0x249f
0x4b,0x1f,0x51,0xf0 = div.f	d15, d15, d1
0x60,0x22           = mov.a	a2, d2
0xde,0x25           = jne	d15, #0x2, #0x2a
0x5e,0x26           = jne	d15, #0x2, #0xc
0x86,0x20           = sha	d0, #0x2
0x82,0x18           = mov	d8, #0x1
0x37,0x5f,0x02,0xf0 = insert	d15, d15, d5, #0, #0x2
0xbf,0x89,0x05,0x80 = jlt.u	d9, #0x8, #0xa
0x5e,0x16           = jne	d15, #0x1, #0xc
0x8f,0xf9,0x01,0xf1 = and	d15, d9, #0x1f
0xbb,0x00,0xc2,0x1b = mov.u	d1, #0xbc20
0x02,0xc4           = mov	d4, d12
0x3c,0x25           = j	#0x4a
0xc2,0xf0           = add	d0, #-0x1
0x15,0xd0,0xc0,0xe3 = stlcx	#0xd0003f80
0xd9,0xff,0x38,0xf2 = lea	a15, [a15]#0x23f8
0x2e,0x1b           = jz.t	d15, #0x1, #0x16
0x3c,0x19           = j	#0x32
0xe2,0x0f           = mul	d15, d0
0x6d,0x00,0x9e,0x03 = call	#0x73c
0x37,0xf0,0x02,0x06 = insert	d0, d0, d15, #0xc, #0x2
0x1e,0x13           = jeq	d15, #0x1, #0x6
0x3c,0x31           = j	#0x62
0xff,0xc9,0x03,0x80 = jge.u	d9, #0xc, #0x6
0xd9,0xff,0x34,0x23 = lea	a15, [a15]#0x30b4
0x37,0x0f,0x05,0xf0 = insert	d15, d15, d0, #0, #0x5
0x91,0x00,0x0c,0xf8 = movh.a	a15, #0x80c0
0x7b,0x80,0x2c,0x04 = movh	d0, #0x42c8
0xbb,0x00,0x40,0x2f = mov.u	d2, #0xf400
0xdf,0x0f,0xb1,0x80 = jne	d15, #0, #0x162
0xf6,0x02           = jnz	d0, #0x4
0x6f,0x7f,0xec,0x7f = jz.t	d15, #0x7, #-0x28
0x3c,0x06           = j	#0xc
0x60,0x14           = mov.a	a4, d1
0x49,0xff,0x00,0x0a = lea	a15, [a15]#0
0x3c,0x12           = j	#0x24
0xd9,0x44,0x20,0x93 = lea	a4, [a4]#0x3260
0x91,0x30,0x00,0xff = movh.a	a15, #0xf003
0x76,0x6d           = jz	d6, #0x1a
0x6f,0x0f,0xf3,0x7f = jz.t	d15, #0, #-0x1a
0xfc,0x6e           = loop	a6, #-0x4
0x6d,0xff,0xac,0xff = call	#-0xa8
0xef,0x4f,0x04,0x00 = jz.t	d15, #0x14, #0x8
0xbb,0x70,0x71,0xfb = mov.u	d15, #0xb717
0x0f,0xf0,0x10,0x00 = sha	d0, d0, d15
0x0f,0x04,0x10,0x40 = sha	d4, d4, d0
0x5e,0x14           = jne	d15, #0x1, #0x8
0x02,0x28           = mov	d8, d2
0x37,0x0f,0x81,0xf7 = insert	d15, d15, d0, #0xf, #0x1
0x37,0xf0,0x87,0x04 = insert	d0, d0, d15, #0x9, #0x7
0xa0,0x66           = mov.a	a6, #0x6
0x37,0x0f,0x02,0xf2 = insert	d15, d15, d0, #0x4, #0x2
0x96,0x40           = or	d15, #0x40
0xc2,0x10           = add	d0, #0x1
0x8b,0x87,0x01,0x00 = add	d0, d7, #0x18
0x91,0x60,0x88,0x4f = movh.a	a4, #0xf886
0x49,0xff,0x20,0x0a = lea	a15, [a15]#0x20
0x6d,0x00,0x0f,0x01 = call	#0x21e
0x3e,0x0e           = jeq	d15, d0, #0x1c
0x3c,0x23           = j	#0x46
0xdf,0x2f,0x91,0xff = jne	d15, #0x2, #-0xde
0x3c,0x0c           = j	#0x18
0x10,0xf2           = addsc.a	a2, a15, d15, #0
0x37,0xf0,0x01,0x0f = insert	d0, d0, d15, #0x1e, #0x1
0xda,0xbc           = mov	d15, #0xbc
0x0f,0x05,0x10,0x50 = sha	d5, d5, d0
0x91,0x00,0x06,0xf8 = movh.a	a15, #0x8060
0x3c,0x27           = j	#0x4e
0xda,0x00           = mov	d15, #0
0x49,0xa5,0x00,0x0a = lea	a5, [sp]#0
0x96,0x02           = or	d15, #0x2
0x37,0x0f,0x81,0xf2 = insert	d15, d15, d0, #0x5, #0x1
0x4b,0x02,0x71,0x41 = ftouz	d4, d2
0x3e,0x0a           = jeq	d15, d0, #0x14
0xa2,0xfc           = sub	d12, d15
0x53,0xc9,0x20,0x00 = mul	d0, d9, #0xc
0xd9,0x44,0xe0,0x22 = lea	a4, [a4]#0x2ca0
0x60,0x4f           = mov.a	a15, d4
0x49,0xa4,0x00,0x0a = lea	a4, [sp]#0
0xb7,0x0f,0x81,0xf0 = insert	d15, d15, #0, #0x1, #0x1
0x4b,0x0f,0x41,0xf1 = itof	d15, d15
0x3e,0x93           = jeq	d15, d9, #0x6
0xd9,0xff,0x0c,0xb0 = lea	a15, [a15]#0x2cc
0x6d,0x00,0x38,0x00 = call	#0x70
0xe2,0x90           = mul	d0, d9
0x4b,0x0f,0x41,0x10 = mul.f	d1, d15, d0
0xa6,0x12           = or	d2, d1
0x4b,0x00,0x41,0xf1 = itof	d15, d0
0x8b,0x14,0x1f,0x00 = add	d0, d4, #-0xf
0x6d,0x00,0x9f,0x09 = call	#0x133e
0x7e,0x92           = jne	d15, d9, #0x4
0x6d,0xff,0x63,0xfb = call	#-0x93a
0x3c,0x33           = j	#0x66
0x6e,0x0e           = jz	d15, #0x1c
0x1d,0x00,0xd4,0x01 = j	#0x3a8
0xbb,0x00,0xa0,0x1b = mov.u	d1, #0xba00
0x6e,0xf6           = jz	d15, #-0x14
0x77,0x00,0x00,0x04 = dextr	d0, d0, d0, #0x8
0x6d,0x00,0xb4,0x07 = call	#0xf68
0x02,0x8f           = mov	d15, d8
0x26,0xf2           = and	d2, d15
0x80,0xf4           = mov.d	d4, a15
0x37,0x04,0xe8,0x0b = extr.u	d0, d4, #0x17, #0x8
0x6d,0xff,0x1f,0xfb = call	#-0x9c2
0x3b,0x00,0x00,0x31 = mov	d3, #0x1000
0x6d,0x00,0x26,0x0e = call	#0x1c4c
0x3e,0x08           = jeq	d15, d0, #0x10
0xd9,0x22,0xb8,0xd2 = lea	a2, [a2]#0x2b78
0x30,0xf3           = add.a	a3, a15
0x91,0x00,0x00,0x27 = movh.a	a2, #0x7000
0x37,0x03,0x68,0x08 = extr.u	d0, d3, #0x10, #0x8
0x91,0x00,0x09,0xf8 = movh.a	a15, #0x8090
0x4b,0x00,0x61,0xf1 = utof	d15, d0
0x6e,0xc9           = jz	d15, #-0x6e
0x9b,0xef,0xcb,0xf4 = addih	d15, d15, #0x4cbe
0x4b,0x0f,0x61,0xf1 = utof	d15, d15
0xd9,0xff,0xb8,0x42 = lea	a15, [a15]#0x2938
0xdf,0x0c,0x9b,0x7f = jeq	d12, #0, #-0xca
0x7b,0xd0,0x38,0x01 = movh	d0, #0x138d
0x53,0x47,0x20,0x00 = mul	d0, d7, #0x4
0x6d,0x00,0xd3,0x0d = call	#0x1ba6
0xbf,0x10,0x15,0x80 = jlt.u	d0, #0x1, #0x2a
0x6d,0x00,0x63,0x00 = call	#0xc6
0x82,0x0a           = mov	d10, #0
0xa6,0x4f           = or	d15, d4
0x53,0x4a,0x20,0xf0 = mul	d15, d10, #0x4
0x37,0xf0,0x81,0xf1 = insert	d15, d0, d15, #0x3, #0x1
0x0f,0x0f,0xb0,0xf1 = clz	d15, d15
0x6d,0x00,0xcd,0x07 = call	#0xf9a
0x91,0x00,0x10,0xf8 = movh.a	a15, #0x8100
0x26,0x32           = and	d2, d3
0x6d,0xff,0x22,0xfb = call	#-0x9bc
0x6d,0x00,0x56,0x01 = call	#0x2ac
0x91,0x00,0x00,0x48 = movh.a	a4, #0x8000
0xbb,0x00,0xc2,0x0b = mov.u	d0, #0xbc20
0x16,0x07           = and	d15, #0x7
0xd9,0xff,0x24,0xf0 = lea	a15, [a15]#0x3e4
0x53,0x41,0x20,0x30 = mul	d3, d1, #0x4
0x0f,0x2f,0x00,0xf0 = sh	d15, d15, d2
0x3b,0x00,0x05,0x40 = mov	d4, #0x50
0xd9,0xff,0x00,0x0e = lea	a15, [a15]#-0x2000
0x91,0x00,0x00,0x80 = movh.a	a8, #0
0x4e,0xf3           = jgtz	d15, #0x6
0x06,0xec           = sh	d12, #-0x2
0x6d,0x00,0xc6,0x07 = call	#0xf8c
0x76,0x03           = jz	d0, #0x6
0x37,0x00,0x62,0xfa = extr.u	d15, d0, #0x14, #0x2
0x57,0x00,0x62,0xff = extr.u	d15, d0, d15, #0x2
0xff,0xc9,0x04,0x80 = jge.u	d9, #0xc, #0x8
0xd9,0xff,0x0c,0x60 = lea	a15, [a15]#0x18c
0x6e,0x30           = jz	d15, #0x60
0x80,0xcf           = mov.d	d15, a12
0xc2,0x11           = add	d1, #0x1
0xdf,0x04,0x3b,0x00 = jeq	d4, #0, #0x76
0xb7,0x7f,0x08,0xf0 = insert	d15, d15, #0x7, #0, #0x8
0x37,0x0f,0x01,0xf6 = insert	d15, d15, d0, #0xc, #0x1
0xd9,0x55,0x08,0x60 = lea	a5, [a5]#0x188
0x42,0xf1           = add	d1, d15
0xa2,0xf0           = sub	d0, d15
0x6d,0xff,0x78,0xfb = call	#-0x910
0x3b,0x00,0xd0,0x02 = mov	d0, #0x2d00
0xd9,0x11,0x00,0x00 = lea	a1, [a1]#0
0x6d,0x88,0x80,0x11 = call	#-0xefdd00
0xda,0x05           = mov	d15, #0x5
0x3c,0x0d           = j	#0x1a
0xe2,0x1f           = mul	d15, d1
0x8f,0x10,0x00,0x01 = and	d0, d0, #0x1
0x15,0xd0,0xc0,0xf7 = stucx	#0xd0003fc0
0xbf,0x89,0x06,0x80 = jlt.u	d9, #0x8, #0xc
0x6f,0x1f,0xfc,0x7f = jz.t	d15, #0x1, #-0x8
0xd9,0xff,0x26,0xb2 = lea	a15, [a15]#0x22e6
0x91,0x40,0x00,0xa7 = movh.a	sp, #0x7004
0xd9,0x22,0x40,0x00 = lea	a2, [a2]#0x400
0x91,0x00,0x00,0x00 = movh.a	a0, #0
0x80,0x41           = mov.d	d1, a4
0x9b,0xe0,0xcb,0x04 = addih	d0, d0, #0x4cbe
0x10,0xdf           = addsc.a	a15, a13, d15, #0
0x91,0xc0,0x88,0x4f = movh.a	a4, #0xf88c
0x40,0xbf           = mov.aa	a15, a11
0xc2,0xf3           = add	d3, #-0x1
0x02,0x49           = mov	d9, d4
0x4b,0xf0,0x51,0xf0 = div.f	d15, d0, d15
0xb7,0x2f,0x08,0xf0 = insert	d15, d15, #0x2, #0, #0x8
0x37,0x0f,0x02,0xf0 = insert	d15, d15, d0, #0, #0x2
0xa6,0xf1           = or	d1, d15
0x10,0xef           = addsc.a	a15, a14, d15, #0
0x49,0xf5,0x00,0x0a = lea	a5, [a15]#0
0x76,0xdb           = jz	d13, #0x16
0x9b,0x8f,0xb9,0xf4 = addih	d15, d15, #0x4b98
0x02,0x2f           = mov	d15, d2
0x3c,0x03           = j	#0x6
0xd9,0x55,0x3c,0x50 = lea	a5, [a5]#0x17c
0xc6,0x30           = xor	d0, d3
0x2e,0x03           = jz.t	d15, #0, #0x6
0xb7,0x4f,0x08,0xf0 = insert	d15, d15, #0x4, #0, #0x8
0x91,0x00,0x06,0xfa = movh.a	a15, #0xa060
0x53,0x4a,0x20,0x10 = mul	d1, d10, #0x4
0x3c,0x0f           = j	#0x1e
0x8f,0xf9,0x03,0xf1 = and	d15, d9, #0x3f
0x4b,0xaf,0x41,0xf0 = mul.f	d15, d15, d10
0x82,0x20           = mov	d0, #0x2
0x0f,0x10,0x00,0x00 = sh	d0, d0, d1
0x37,0x0f,0x82,0xf2 = insert	d15, d15, d0, #0x5, #0x2
0x3c,0x0a           = j	#0x14
0x3c,0x13           = j	#0x26
0x6d,0x00,0xe7,0x07 = call	#0xfce
0x3f,0x40,0xe3,0xff = jlt.u	d0, d4, #-0x3a
0x8f,0x21,0x00,0xf0 = sh	d15, d1, #0x2
0x6f,0x0f,0xfe,0xff = jnz.t	d15, #0, #-0x4
0x37,0xf0,0x03,0xf0 = insert	d15, d0, d15, #0, #0x3
0x4b,0x0f,0x71,0xf1 = ftouz	d15, d15
0x91,0x10,0x00,0xf1 = movh.a	a15, #0x1001
0x3c,0x01           = j	#0x2
0x06,0x63           = sh	d3, #0x6
0xd9,0x44,0xb0,0xd2 = lea	a4, [a4]#0x2b70
0x1d,0x00,0x9c,0x00 = j	#0x138
0x02,0x84           = mov	d4, d8
0x89,0xcf,0x8a,0x28 = st.h	[a12]#0x8a, d15
0x6d,0x00,0x41,0x01 = call	#0x282
0xa6,0x30           = or	d0, d3
0x3c,0xfe           = j	#-0x4
0x16,0x01           = and	d15, #0x1
0x3e,0x67           = jeq	d15, d6, #0xe
0x4b,0xf1,0x51,0x20 = div.f	d2, d1, d15
0xa6,0x0f           = or	d15, d0
0x7f,0x20,0x09,0x80 = jge.u	d0, d2, #0x12
0x53,0x47,0x20,0x10 = mul	d1, d7, #0x4
0x4b,0xf1,0x51,0x00 = div.f	d0, d1, d15
0x8b,0x60,0x09,0xf1 = rsub	d15, d0, #0x96
0xdf,0x1f,0xfa,0x7f = jeq	d15, #0x1, #-0xc
0xee,0xf6           = jnz	d15, #-0x14
0x82,0xf3           = mov	d3, #-0x1
0x53,0xcf,0x20,0xf0 = mul	d15, d15, #0xc
0x91,0x00,0x00,0xf7 = movh.a	a15, #0x7000
0x3c,0x94           = j	#-0xd8
0x40,0xc4           = mov.aa	a4, a12
0xc2,0xe0           = add	d0, #-0x2
0x91,0x00,0x00,0x90 = movh.a	a9, #0
0x91,0x00,0x00,0x57 = movh.a	a5, #0x7000