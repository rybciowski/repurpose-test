import ffmpeg
import subprocess
import os
import math # Do PI
import uuid
import pathlib

def get_video_duration_and_frames(filepath):
    """Pobiera czas trwania i liczbę klatek wideo za pomocą ffprobe."""
    try:
        probe_filepath = pathlib.Path(filepath).as_posix()
        probe = ffmpeg.probe(probe_filepath)
        video_stream = next((stream for stream in probe['streams'] if stream['codec_type'] == 'video'), None)
        if video_stream:
            duration_str = video_stream.get('duration')
            nb_frames_str = video_stream.get('nb_frames')
            duration = float(duration_str) if duration_str and duration_str != 'N/A' else None
            if nb_frames_str and nb_frames_str != 'N/A':
                nb_frames = int(nb_frames_str)
            elif duration and video_stream.get('avg_frame_rate') and video_stream.get('avg_frame_rate') != '0/0':
                try:
                    num_str, den_str = video_stream['avg_frame_rate'].split('/')
                    num = int(num_str); den = int(den_str)
                    fps = num / den if den != 0 else 0
                    nb_frames = int(duration * fps) if fps > 0 else None
                except (ValueError, ZeroDivisionError, AttributeError): nb_frames = None 
            else: nb_frames = None
            return duration, nb_frames
        return None, None
    except ffmpeg.Error as e:
        print(f"Błąd ffprobe: {e.stderr.decode('utf8') if e.stderr else str(e)}")
        return None, None
    except Exception as e_gen:
        print(f"Ogólny błąd w get_video_duration_and_frames: {str(e_gen)}")
        return None, None

def process_video_ffmpeg(input_filepath, output_filepath, settings):
    print(f"Rozpoczynanie przetwarzania: {input_filepath} -> {output_filepath}")
    print(f"Ustawienia: {settings}")

    unique_suffix = uuid.uuid4().hex
    base_dir = os.path.dirname(input_filepath) # To będzie nasz CWD dla vidstabdetect

    # Nazwy plików (bez pełnych ścieżek na razie dla tych, które będą tworzone w base_dir)
    simple_transforms_filename = f'transforms_{unique_suffix}.trf'
    
    # Pełne ścieżki do plików tymczasowych i wynikowych
    full_transforms_filepath_obj = pathlib.Path(base_dir) / simple_transforms_filename
    temp_video_s2_filepath_obj = pathlib.Path(base_dir) / f'temp_s2_{unique_suffix}.mp4'
    temp_audio_s3_filepath_obj = pathlib.Path(base_dir) / f'temp_s3_{unique_suffix}.m4a'
    temp_video_s4_filepath_obj = pathlib.Path(base_dir) / f'temp_s4_denoised_{unique_suffix}.mp4'

    # Stringowe wersje pełnych ścieżek (dla os.path itp.)
    full_transforms_file_str = str(full_transforms_filepath_obj)
    temp_video_s2_filename_str = str(temp_video_s2_filepath_obj)
    temp_audio_s3_filename_str = str(temp_audio_s3_filepath_obj)
    temp_video_s4_filename_str = str(temp_video_s4_filepath_obj)

    # Ścieżki w formacie POSIX dla biblioteki ffmpeg-python i niektórych poleceń subprocess
    input_filepath_posix = pathlib.Path(input_filepath).as_posix()
    # Dla vidstabtransform w ffmpeg-python użyjemy pełnej ścieżki POSIX
    full_transforms_file_posix_for_lib = full_transforms_filepath_obj.as_posix() 
    temp_video_s2_posix = temp_video_s2_filepath_obj.as_posix()
    temp_audio_s3_posix = temp_audio_s3_filepath_obj.as_posix()
    temp_video_s4_posix = temp_video_s4_filepath_obj.as_posix()
    output_filepath_posix = pathlib.Path(output_filepath).as_posix()

    temp_files_to_remove = [temp_video_s2_filename_str, temp_audio_s3_filename_str, temp_video_s4_filename_str, full_transforms_file_str]

    try:
        if settings.get('stabilizacja_enabled', False):
            print("Krok 1: Analiza drgań wideo (vidstabdetect)...")
            # Używamy input_filepath_posix, bo ffmpeg jako CLI może lepiej działać z POSIX ścieżkami wejściowymi
            # Dla `result=` używamy TYLKO NAZWY PLIKU, a `cwd` ustawiamy na `base_dir`
            vidstab_analyze_command = [
                'ffmpeg', '-y', '-i', input_filepath_posix, 
                '-vf', f'vidstabdetect=result={simple_transforms_filename}:shakiness=5:accuracy=15',
                '-f', 'null', '-'
            ]
            print(f"Polecenie vidstabdetect (cwd={base_dir}): {' '.join(vidstab_analyze_command)}")
            process_result = subprocess.run(
                vidstab_analyze_command, 
                cwd=base_dir,  # <--- USTAWIANIE KATALOGU ROBOCZEGO
                check=False, 
                capture_output=True, 
                text=True, 
                shell=False
            )
            if process_result.returncode != 0:
                print(f"Błąd vidstabdetect: {process_result.stderr}")
                raise subprocess.CalledProcessError(process_result.returncode, vidstab_analyze_command, output=process_result.stdout, stderr=process_result.stderr)
            
            # Sprawdźmy, czy plik .trf faktycznie powstał w base_dir
            if not os.path.exists(full_transforms_file_str):
                print(f"KRYTYCZNY BŁĄD: Plik transformacji {full_transforms_file_str} nie został utworzony po vidstabdetect!")
                # Można rzucić wyjątek lub próbować kontynuować bez stabilizacji
                raise FileNotFoundError(f"Plik transformacji {full_transforms_file_str} nie został utworzony.")
            print(f"Krok 1 zakończony. Utworzono plik transformacji: {full_transforms_file_str}")


        video_input_stream = ffmpeg.input(input_filepath_posix)
        audio_input_stream = ffmpeg.input(input_filepath_posix)
        processed_video = video_input_stream.video

        print("\nKrok 2: Aplikowanie filtrów wideo...")
        if settings.get('stabilizacja_enabled', False) and os.path.exists(full_transforms_file_str):
            smoothing = settings.get('stabilizacja_smoothing', 10)
            zoom_stab_ui = settings.get('stabilizacja_zoom', 0) 
            zoom_stab_ffmpeg = zoom_stab_ui / 100.0
            # Dla biblioteki ffmpeg-python, pełna ścieżka (najlepiej POSIX) jest zazwyczaj OK
            processed_video = processed_video.filter('vidstabtransform', input=full_transforms_file_posix_for_lib, zoom=zoom_stab_ffmpeg, smoothing=smoothing)

        # ... (reszta filtrów wideo - BEZ ZMIAN, używają `processed_video`)
        if settings.get('przysp_wideo_enabled', False):
            percent = settings.get('przysp_wideo_percent', 3)
            if percent > 0:
                multiplier = 1.0 + (percent / 100.0)
                processed_video = processed_video.filter('setpts', f'PTS/{multiplier}')
            elif percent < 0: 
                if percent > -100 :
                     multiplier = 1.0 / (1.0 + (percent / 100.0))
                     processed_video = processed_video.filter('setpts', f'PTS*{multiplier}')
        if settings.get('odbicie_lustrzane_enabled', False):
            processed_video = processed_video.filter('hflip')
        if settings.get('obrot_wideo_enabled', False):
            degrees = settings.get('obrot_wideo_degrees', 1)
            if degrees != 0:
                processed_video = processed_video.filter('rotate', f'{degrees}*PI/180')
        if settings.get('crop_wideo_enabled', False):
            pixels = settings.get('crop_wideo_pixels', 10)
            if pixels > 0:
                processed_video = processed_video.filter('crop', w=f'iw-{pixels*2}', h=f'ih-{pixels*2}')
                processed_video = processed_video.filter('scale', w='iw', h='ih')
        if settings.get('jasnosc_enabled', False):
            val_ui = settings.get('jasnosc_value', 2)
            val_ffmpeg = val_ui / 100.0
            processed_video = processed_video.filter('eq', brightness=val_ffmpeg)
        if settings.get('kontrast_enabled', False):
            val_ui = settings.get('kontrast_value', 15)
            val_ffmpeg = 1.0 + (val_ui / 100.0)
            processed_video = processed_video.filter('eq', contrast=val_ffmpeg)
        if settings.get('nasycenie_enabled', False):
            val_ui = settings.get('nasycenie_value', 5)
            val_ffmpeg = 1.0 + (val_ui / 100.0)
            processed_video = processed_video.filter('eq', saturation=val_ffmpeg)
        if settings.get('gamma_enabled', False):
            val_ui = settings.get('gamma_value', 10)
            val_ffmpeg = val_ui / 10.0 
            if val_ffmpeg <= 0: val_ffmpeg = 0.01
            processed_video = processed_video.filter('eq', gamma=val_ffmpeg)
        if settings.get('hue_enabled', False):
            degrees = settings.get('hue_degrees', 10)
            processed_video = processed_video.filter('hue', h=degrees, s=1) 
        if settings.get('curves_strong_contrast_enabled', False):
            processed_video = processed_video.filter('curves', preset='strong_contrast')
        if settings.get('szum_enabled', False):
            alls_val_ui = settings.get('szum_alls', 5)
            processed_video = processed_video.filter('noise', alls=alls_val_ui, allf='t+u')
        if settings.get('gblur_enabled', False):
            sigma_val_ui = settings.get('gblur_sigma_ui', 30)
            sigma_val_ffmpeg = sigma_val_ui / 100.0
            if sigma_val_ffmpeg > 0:
                processed_video = processed_video.filter('gblur', sigma=sigma_val_ffmpeg)
        if settings.get('boxblur_enabled', False):
            radius_ui = settings.get('boxblur_luma_radius', 2)
            if radius_ui > 0:
                power_ffmpeg = max(1, math.ceil(radius_ui / 2.0)) 
                processed_video = processed_video.filter('boxblur', luma_radius=radius_ui, luma_power=int(power_ffmpeg))
        if settings.get('unsharp_enabled', False):
            msize = settings.get('unsharp_luma_msize', 5)
            amount = settings.get('unsharp_luma_amount', 1.5)
            processed_video = processed_video.filter('unsharp', luma_msize_x=msize, luma_msize_y=msize, luma_amount=amount)
        if settings.get('colorbalance_shadows_enabled', False):
            shadow_adjust_ui = settings.get('colorbalance_shadows_rs_ui', 0.3)
            processed_video = processed_video.filter('colorbalance', rs=shadow_adjust_ui, gs=shadow_adjust_ui, bs=shadow_adjust_ui)
        if settings.get('motion_blur_enabled', False):
            processed_video = processed_video.filter('minterpolate', fps=150, mi_mode='mci', scd='none')
            processed_video = processed_video.filter('tblend', all_mode='average')
            processed_video = processed_video.filter('framerate', fps=30) 
        if settings.get('lenscorrection_enabled', False):
            k_val_ui = settings.get('lenscorrection_k1k2_ui', 2)
            k_ffmpeg = k_val_ui / 100.0
            processed_video = processed_video.filter('lenscorrection', k1=k_ffmpeg, k2=k_ffmpeg)
        if settings.get('vignette_enabled', False):
            processed_video = processed_video.filter('vignette') 
        duration_sec, total_frames = get_video_duration_and_frames(input_filepath)
        print(f"Odczytano: czas trwania {duration_sec}s, klatki: {total_frames}")
        if settings.get('fade_in_enabled', False):
            nb_frames_ui = settings.get('fade_in_nb_frames', 30)
            if nb_frames_ui > 0:
                 processed_video = processed_video.filter('fade', type='in', start_frame=0, nb_frames=nb_frames_ui)
        if settings.get('fade_out_enabled', False) and total_frames is not None and total_frames > 0:
            nb_frames_fade_out_ui = settings.get('fade_out_nb_frames', 30)
            if nb_frames_fade_out_ui > 0:
                start_fade_out = total_frames - nb_frames_fade_out_ui
                if start_fade_out < 0: start_fade_out = 0 
                processed_video = processed_video.filter('fade', type='out', start_frame=int(start_fade_out), nb_frames=nb_frames_fade_out_ui)
        processed_video = processed_video.filter('format', 'yuv420p')
        # --- Koniec filtrów wideo ---
        
        (
            ffmpeg
            .output(processed_video, temp_video_s2_posix, vcodec='libx264', preset='medium', crf=23)
            .global_args('-hide_banner', '-loglevel', 'error')
            .run(overwrite_output=True, capture_stdout=True, capture_stderr=True)
        )
        print(f"Krok 2 zakończony. Zapisano przetworzone wideo do: {temp_video_s2_filename_str}")

        print("\nKrok 3: Przetwarzanie audio...")
        processed_audio = audio_input_stream.audio
        if settings.get('audio_prep_enabled', False):
            silence_duration = settings.get('audio_prep_silence_duration', 1.5)
            if silence_duration > 0:
                silent_segment = ffmpeg.input(f'aevalsrc=exprs=0:d={silence_duration}:sample_rate=44100:channel_layout=stereo', format='lavfi').audio.filter('asetpts', 'PTS-STARTPTS')
                original_audio_duration, _ = get_video_duration_and_frames(input_filepath)
                if original_audio_duration is not None and original_audio_duration > silence_duration:
                    original_trimmed = audio_input_stream.audio.filter('atrim', start=silence_duration).filter('asetpts', 'PTS-STARTPTS')
                    processed_audio = ffmpeg.filter([silent_segment, original_trimmed], 'concat', n=2, v=0, a=1)
                else:
                    processed_audio = silent_segment
        if settings.get('przysp_audio_enabled', False):
            percent_audio_ui = settings.get('przysp_audio_percent', 3)
            if percent_audio_ui != 0: 
                audio_multiplier = 1.0 + (percent_audio_ui / 100.0)
                if audio_multiplier > 0:
                    if audio_multiplier >= 0.5 and audio_multiplier <= 2.0:
                         processed_audio = processed_audio.filter('atempo', audio_multiplier)
                    elif audio_multiplier > 2.0:
                        temp_atempo = audio_multiplier; chain_atempo_values = []
                        while temp_atempo > 2.0: chain_atempo_values.append(2.0); temp_atempo /= 2.0
                        if temp_atempo > 0.5 : chain_atempo_values.append(temp_atempo)
                        if chain_atempo_values:
                            for val in chain_atempo_values: processed_audio = processed_audio.filter('atempo', val)
                    elif audio_multiplier < 0.5 and audio_multiplier > 0:
                        temp_atempo = audio_multiplier; chain_atempo_values = []
                        while temp_atempo < 0.5 and len(chain_atempo_values) < 5: chain_atempo_values.append(0.5); temp_atempo /= 0.5
                        if temp_atempo < 2.0 and temp_atempo > 0: chain_atempo_values.append(temp_atempo)
                        if chain_atempo_values:
                           for val in chain_atempo_values: processed_audio = processed_audio.filter('atempo', val)
        (
            ffmpeg
            .output(processed_audio, temp_audio_s3_posix, acodec='aac', audio_bitrate='192k')
            .global_args('-hide_banner', '-loglevel', 'error')
            .run(overwrite_output=True, capture_stdout=True, capture_stderr=True)
        )
        print(f"Krok 3 zakończony. Zapisano przetworzone audio do: {temp_audio_s3_filename_str}")

        current_video_to_process_for_muxing_ffmpeg_posix = temp_video_s2_posix
        current_video_to_process_for_muxing_str = temp_video_s2_filename_str

        if settings.get('hqdn3d_enabled', False):
            print(f"\nKrok 4: Odszumianie wideo (hqdn3d) dla {temp_video_s2_filename_str}...")
            denoise_command = [
                'ffmpeg', '-y', '-i', temp_video_s2_posix, 
                '-vf', 'hqdn3d=1.5:1.5:6:6', 
                '-an', 
                '-vcodec', 'libx264', '-preset', 'medium', '-crf', '23',
                '-loglevel', 'error',
                temp_video_s4_posix
            ]
            print(f"Polecenie hqdn3d: {' '.join(denoise_command)}")
            process_result_denoise = subprocess.run(denoise_command, check=False, capture_output=True, text=True, shell=False)
            if process_result_denoise.returncode != 0:
                print(f"Błąd hqdn3d: {process_result_denoise.stderr}")
                print("Odszumianie nie powiodło się, kontynuacja bez odszumiania.")
            else:
                current_video_to_process_for_muxing_ffmpeg_posix = temp_video_s4_posix
                current_video_to_process_for_muxing_str = temp_video_s4_filename_str
                print(f"Krok 4 zakończony. Zapisano odszumione wideo do: {temp_video_s4_filename_str}")
        else:
            print("Krok 4: Odszumianie wideo (hqdn3d) pominięte.")

        print(f"\nKrok 5: Łączenie wideo ({current_video_to_process_for_muxing_str}) i audio ({temp_audio_s3_filename_str})...")
        final_video_input = ffmpeg.input(current_video_to_process_for_muxing_ffmpeg_posix)
        final_audio_input = ffmpeg.input(temp_audio_s3_posix)
        (
            ffmpeg
            .output(final_video_input.video, final_audio_input.audio, output_filepath_posix, vcodec='copy', acodec='copy', shortest=None)
            .global_args('-hide_banner', '-loglevel', 'error')
            .run(overwrite_output=True, capture_stdout=True, capture_stderr=True)
        )
        print(f"Krok 5 zakończony. Zapisano ostateczny plik: {output_filepath}")
        
        return True, output_filepath

    except ffmpeg.Error as e:
        error_message = e.stderr.decode('utf8') if e.stderr else str(e)
        print(f"Błąd FFmpeg: {error_message}")
        if os.path.exists(output_filepath) and os.path.getsize(output_filepath) == 0:
            try: os.remove(output_filepath)
            except: pass
        return False, f"Błąd FFmpeg: {error_message}"
    except subprocess.CalledProcessError as e:
        error_message = e.stderr if e.stderr else str(e.output)
        print(f"Błąd subprocess (FFmpeg CLI): {error_message}")
        if os.path.exists(output_filepath) and os.path.getsize(output_filepath) == 0:
            try: os.remove(output_filepath)
            except: pass
        return False, f"Błąd subprocess (FFmpeg CLI): {error_message}"
    except Exception as e:
        import traceback
        print(f"Nieoczekiwany błąd: {str(e)}")
        traceback.print_exc()
        if os.path.exists(output_filepath) and os.path.getsize(output_filepath) == 0:
            try: os.remove(output_filepath)
            except: pass
        return False, f"Nieoczekiwany błąd: {str(e)}"
    finally:
        print("\nKrok 6: Usuwanie plików tymczasowych...")
        for f_path in temp_files_to_remove:
            if os.path.exists(f_path):
                try:
                    os.remove(f_path)
                    print(f"Usunięto: {f_path}")
                except Exception as e_rem:
                    print(f"Nie udało się usunąć {f_path}: {e_rem}")