# --- PRZETWARZANIE WIDEO ---
# STABILIZACJA (VIDSTABTRANSFORM)
processed_video = stream_video_input_s2.video.filter('vidstabtransform', input=transforms_file, zoom=0, smoothing=10)
# PRZYSPIESZANIE WIDEO
DOMYŚLNE - 3%
# ODBICIE LUSTRZANE
processed_video = processed_video.filter('hflip')
# OBRÓT WIDEO O 1 STOPIEŃ
DOMYŚLNIE - 1 
# EFEKT CYFROWEGO ZOOMU
processed_video = processed_video.filter('crop', w='in_w-10', h='in_h-10').filter('scale', w='iw', h='ih')
# JASNOŚĆ
DOMYŚLNIE - 2 
# KONTRAST
DOMYŚLNIE - 15
# NASYCENIE
DOMYŚLNIE - 5
# GAMMA
DOMYŚLNIE - 10
# PRZESUNIĘCIE BARWY (HUE)
processed_video = processed_video.filter('hue', h=10, s=1)
# KOREKTA TONALNA (KRZYWE - MOCNY KONTRAST)
processed_video = processed_video.filter('curves', preset='strong_contrast')
# DODANIE SZUMU (NOISE)
processed_video_noise = processed_video.filter('noise', alls=5, allf='t+u')
# ROZMYCIE GAUSSOWSKIE (BLUR)
processed_video_gblur = processed_video_noise.filter('gblur', sigma=0.3)
# ROZMYCIE PUDEŁKOWE (BOXBLUR) - ZMIANA TUTAJ
processed_video_boxblur = processed_video_gblur.filter('boxblur', luma_radius=2, luma_power=1)
# WYOSTRZANIE (UNSHARP MASK)
processed_video_unsharp = processed_video_boxblur.filter('unsharp', luma_msize_x=5, luma_msize_y=5, luma_amount=1.5)
# BALANS KOLORÓW (ROZJAŚNIENIE CIENI)
processed_video_colorbalance = processed_video_unsharp.filter('colorbalance', rs=.3, gs=.3, bs=.3)
# ZAAWANSOWANE ROZMYCIE W RUCHU (MINTERPOLATE + TBLEND + FRAMERATE)
processed_video_interpolated = processed_video_colorbalance.filter('minterpolate', fps=150, mi_mode='mci')
processed_video_motion_blurred = processed_video_interpolated.filter('tblend', all_mode='average')
processed_video_final_framerate = processed_video_motion_blurred.filter('framerate', fps=30)
# KOREKCJA OBIEKTYWU
processed_video_lenscorrected = processed_video_final_framerate.filter('lenscorrection', k1=0.02, k2=0.02)
# EFEKT WINIETY (VIGNETTE)
processed_video_vignette = processed_video_lenscorrected.filter('vignette')
# EFEKT FADE-IN (ROZJAŚNIANIE NA POCZĄTKU)
processed_video_fade_in = processed_video_vignette.filter('fade', type='in', start_frame=0, nb_frames=30)
# EFEKT FADE-OUT (ŚCIEMNIANIE POD KONIEC)
processed_video_fade_out = processed_video_fade_in.filter('fade', type='out', start_frame=300, nb_frames=30)
