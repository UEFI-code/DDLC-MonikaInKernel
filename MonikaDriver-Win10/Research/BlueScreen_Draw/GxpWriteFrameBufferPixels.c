__int64 __fastcall GxpWriteFrameBufferPixels(unsigned __int64 a1, _DWORD *a2)
{
  _DWORD *v2; // r14
  __int64 param1; // rdi
  unsigned int v4; // r13d
  __int64 v5; // rdx
  __int64 v6; // rcx
  __int64 v7; // r8
  __int64 v8; // r9
  unsigned int BitsPerPixel; // r15d
  __int64 result; // rax
  int v11; // r11d
  int v12; // esi
  unsigned int v13; // r15d
  unsigned int v14; // r10d
  __int64 v15; // rsi
  __int64 gpu_buf_relative; // rsi
  int v17; // r8d
  int v18; // eax
  int v19; // ebx
  int v20; // ecx
  unsigned int v21; // eax
  unsigned int v22; // edx
  __int64 frame_template_11; // rdi
  __int64 size_relative; // r12
  __int64 v25; // r13
  __int64 v26; // r14
  int RotatedPixelOffset; // ebx
  char *v28; // rsi
  __int64 v29; // r9
  unsigned int v30; // esi
  __int64 v31; // r12
  char *v32; // [rsp+30h] [rbp-D0h] BYREF
  int v33; // [rsp+38h] [rbp-C8h] BYREF
  unsigned __int64 v34; // [rsp+40h] [rbp-C0h] BYREF
  unsigned int v35; // [rsp+48h] [rbp-B8h]
  unsigned __int64 v36; // [rsp+50h] [rbp-B0h] BYREF
  int v37; // [rsp+58h] [rbp-A8h]
  unsigned int v38; // [rsp+60h] [rbp-A0h]
  __int64 v39; // [rsp+68h] [rbp-98h] BYREF
  __int64 v40; // [rsp+70h] [rbp-90h] BYREF
  unsigned __int64 param1_1; // [rsp+80h] [rbp-80h] BYREF
  int v42; // [rsp+88h] [rbp-78h]
  _DWORD *v2_shadow; // [rsp+90h] [rbp-70h] BYREF
  int v44; // [rsp+98h] [rbp-68h]
  int v45[2]; // [rsp+A0h] [rbp-60h] BYREF
  int v46; // [rsp+A8h] [rbp-58h]
  int v47; // [rsp+ACh] [rbp-54h]
  __int64 frame_template_111; // [rsp+B0h] [rbp-50h]
  unsigned __int64 v49; // [rsp+B8h] [rbp-48h]
  __int64 frame_template_1; // [rsp+C8h] [rbp-38h]
  __int64 v51; // [rsp+D0h] [rbp-30h]
  char v52[80]; // [rsp+E0h] [rbp-20h] BYREF

  v2_shadow = a2;
  v2 = a2;
  param1_1 = a1;
  param1 = a1;
  v51 = 0LL;
  v49 = 0LL;
  v34 = 0LL;
  v35 = 0;
  memset(v52, 0LL, 72LL);
  v4 = 0;
  v40 = 0LL;
  v39 = 0LL;
  v32 = 0LL;
  v33 = 0;
  BitsPerPixel = BgpGetBitsPerPixel(v6, v5, v7, v8);
  v36 = __PAIR64__(DWORD1(BgInternal), DWORD2(BgInternal));
  v37 = HIDWORD(BgInternal);
  if ( !param1 || !*(_DWORD *)(param1 + 4) || !*(_DWORD *)param1 || *(_DWORD *)(param1 + 8) != BitsPerPixel || !v2 )
    return 3221225485LL;
  if ( (dword_140C19DD0 & 2) == 0 )
    return 3221225473LL;
  result = GxpAdjustRectangleToFrameBuffer(param1, (_DWORD)v2, (unsigned int)&v36, (unsigned int)&v40, (__int64)&v39, 1);
  if ( (int)result >= 0 )
  {
    if ( (_BYTE)BgInternal )
    {
      v11 = v37;
      v12 = v37 * v2[1];
      v13 = BitsPerPixel >> 3;
      v14 = v13 * v40;
      frame_template_1 = *(_QWORD *)(param1 + 24);
      v15 = v13 * (*v2 + v12);
      v38 = v13 * v40;
      gpu_buf_relative = qword_140C19D80 + v15;
      if ( !BYTE2(BgInternal) )
      {
LABEL_10:
        v17 = *(_DWORD *)(param1 + 4);
        v18 = v17;
        v19 = *(_DWORD *)param1;
        v20 = *(_DWORD *)param1;
LABEL_11:
        v21 = v13 * v18;
        v22 = v13 * v37;
        v34 = __PAIR64__(v19, v21);
        v35 = v13 * v37;
        if ( BYTE2(BgInternal) )
        {
          v49 = __PAIR64__(v20, v17);
          v30 = 0;
          HIDWORD(v32) = 0;
          if ( v20 )
          {
            while ( 1 )
            {
              LODWORD(v32) = 0;
              v31 = *(_QWORD *)(param1 + 24) + v14 * v30;
              if ( *(_DWORD *)(param1 + 4) )
                break;
LABEL_45:
              ++v30;
              v4 = 0;
              HIDWORD(v32) = v30;
              if ( v30 >= *(_DWORD *)param1 )
                goto LABEL_16;
            }
            v2_shadow = (_DWORD *)v36;
            param1_1 = v49;
            v44 = v11;
            v42 = v51;
            while ( 1 )
            {
              RotatedPixelOffset = GxpGetRotatedPixelOffset(
                                     (int)v32,
                                     (int)&param1_1,
                                     (int)v2,
                                     (int)&v2_shadow,
                                     (__int64)&v33);
              if ( RotatedPixelOffset < 0 )
                goto LABEL_19;
              memmove(qword_140C19D80 + v13 * v33, v31, v13);
              ++v4;
              v31 += v13;
              LODWORD(v32) = v4;
              if ( v4 >= *(_DWORD *)(param1 + 4) )
              {
                v14 = v38;
                v11 = v37;
                goto LABEL_45;
              }
            }
          }
        }
        else if ( v19 )
        {
          frame_template_11 = frame_template_1;
          size_relative = v21;
          v32 = (char *)v22;
          v25 = v14;
          v26 = v22;
          do
          {
            memmove(gpu_buf_relative, frame_template_11, size_relative);
            frame_template_11 += v25;
            gpu_buf_relative += v26;
            --v19;
          }
          while ( v19 );
          param1 = param1_1;
          v2 = v2_shadow;
        }
LABEL_16:
        if ( qword_140C19F30 )
          BgfxGrowDirtyRect(&v34, v2, v13);
LABEL_18:
        RotatedPixelOffset = 0;
LABEL_19:
        *(_DWORD *)param1 = HIDWORD(v40);
        *(_DWORD *)(param1 + 4) = v40;
        *(_QWORD *)v2 = v39;
        return (unsigned int)RotatedPixelOffset;
      }
      if ( BYTE2(BgInternal) != 1 )
      {
        if ( BYTE2(BgInternal) == 2 )
          goto LABEL_10;
        if ( BYTE2(BgInternal) != 3 )
        {
          RotatedPixelOffset = -1073741811;
          goto LABEL_19;
        }
      }
      v20 = *(_DWORD *)param1;
      v18 = *(_DWORD *)param1;
      v19 = *(_DWORD *)(param1 + 4);
      v17 = v19;
      goto LABEL_11;
    }
    v28 = 0LL;
    v45[0] = *(_DWORD *)param1;
    v45[1] = *(_DWORD *)(param1 + 4);
    v32 = 0LL;
    if ( (dword_140C19DD0 & 8) == 0 )
    {
      v47 = *(_DWORD *)(param1 + 12);
      frame_template_111 = *(_QWORD *)(param1 + 24);
      v46 = xmmword_140C19D70;
      goto LABEL_29;
    }
    if ( (dword_140C19DD0 & 0xC00) != 0 )
    {
      v29 = 1LL;
      v32 = v52;
    }
    else
    {
      v29 = 0LL;
    }
    result = BgpGxConvertRectangleEx(param1, 4LL, &v32, v29);
    if ( (int)result >= 0 )
    {
      v28 = v32;
      v47 = *((_DWORD *)v32 + 3);
      frame_template_111 = *((_QWORD *)v32 + 3);
      v46 = 1;
LABEL_29:
      RotatedPixelOffset = ((__int64 (__fastcall *)(int *, _DWORD *, _QWORD))qword_140C19D80)(v45, v2, 0LL);
      if ( v28 && v28 != v52 )
        BgpGxRectangleDestroy(v28);
      if ( RotatedPixelOffset < 0 )
        goto LABEL_19;
      goto LABEL_18;
    }
  }
  return result;
}