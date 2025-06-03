PRZETWARZANIE WIDEO
Skrypt (transformacja): vidstabtransform, zoom=0, smoothing=10
Ustawienia na stronie wyświetlanie w normalnych liczbach zakres 0-30
Domyślnie 10 odpowiadające input=transforms_file, zoom=0, smoothing=10
Dodać suwak od wartosci zoom, z zakresem liczb 0-20, domyślnie wartośc 0 odpowiadajaca zoom=0
-
Skrypt: setpts, 'PTS/1.03' (przyspieszenie 1.03x)
Ustawienia na stronie wyświetlanie w % zakres 0-30
Domyślnie 3% odpowiadające 'PTS/1.03'
-
Skrypt: hflip (włącza odbicie lustrzane)
Ustawienia na stronie (Tylko opcja włączenie lub wyłączenia):
-
Skrypt: rotate, '1*PI/180' (obraca o 1 stopień)
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-30
Domyślna wartośc na stronie 1 odpowiadajaca '1*PI/180'
-
Skrypt: crop, w='in_w-10', h='in_h-10' (przycięcie o 10px z każdej strony, co daje efekt zoomu po przeskalowaniu)
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-30
Domyślna wartość na stronie 10 odpowiadajaca w='in_w-10', h='in_h-10'
-
Skrypt: eq, brightness=0.02 
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-30
Domyślna wartośc na stronie 2 odpowiadajaca brightness=0.02 
-
Skrypt: eq, contrast=1.15 
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-40
Domyślna wartośc na stronie 15 odpowiadajaca contrast=1.15
-
Skrypt: eq, saturation=1.05
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-40
Domyślna wartośc na stronie 5 odpowiadajaca saturation=1.05
-
Skrypt: eq, gamma=1.1
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-40
Domyślna wartośc na stronie 10 odpowiadajaca gamma=1.1
-
Skrypt: hue, h=10, s=1 (przesunięcie barwy o 10 stopni, s=1 oznacza zachowanie oryginalnego nasycenia w kontekście tego filtra)
stawienia na stronie wyświetlane w normalnych liczbach, zakres -180 do 180
Domyślna wartośc na stronie 10 odpowiadajaca Skrypt: hue, h=10, s=1, / s=1 jest stale.
-
Skrypt: curves, preset='strong_contrast' (stosuje predefiniowany zestaw krzywych dla mocnego kontrastu)
Suwak - do usunięcia 
Ustawienia na stronie, Tylko przełącznik on/off. Jeśli włączone, stosuje domyślnie curves, preset='strong_contrast'
-
Skrypt: noise, alls=5, allf='t+u' (alls=5: siła szumu 0-100, allf='t+u': flagi rodzaju szumu)
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-40
Domyślna wartośc na stronie 5 alls=5, allf='t+u'
-
Skrypt: gblur, sigma=0.3 (sigma: siła rozmycia, mniejsze wartości = subtelniejsze)
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-70
Domyślna wartośc na stronie 30 odpowiadajaca sigma=0.3
-
Skrypt: ('boxblur', luma_radius=2, luma_power=1)
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-10
Domyślna wartośc na stronie 2 odpowiadajaca ('boxblur', luma_radius=2, luma_power=1), 1 bedzie opowiadać ('boxblur', luma_radius=1, luma_power=0.5) ect.
-
Skrypt: unsharp, luma_msize_x=5, luma_msize_y=5, luma_amount=1.5
Dodać oddzielny brakujacy suwak
luma_msize_x/y: Rozmiar matrycy (3-23). Domyślnie 5 odpowiadajace luma_msize_x=5, luma_msize_y=5
luma_amount: Siła wyostrzania (-1.5 do 1.5). Domyślnie 1.5 odpowiadajace luma_amount=1.5, mozliwosc zmiany na pasku co 0.5
-
Skrypt: colorbalance, rs=.3, gs=.3, bs=.3 (regulacja cieni dla R, G, B; zakres -1.0 do 1.0)
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres -1 do 1 co 0.10
Domyślna wartośc na stronie 0.30 odpowiadajaca colorbalance, rs=.3, gs=.3, bs=.3
-
Skrypt: minterpolate, fps=150, mi_mode='mci', następnie tblend, all_mode='average', następnie framerate, fps=30 (zwiększa klatki, blenduje, przywraca fps)
Suwak - do usunięcia lub uproszczenia.
Mapowanie: Tylko przełącznik on/off. Jeśli włączone, stosuje całą sekwencję ze skryptu.
-
Skrypt: lenscorrection, k1=0.02, k2=0.02 (parametry zniekształceń radialnych)
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-100 
Domyślna wartośc na stronie 2 odpowiadajaca lenscorrection, k1=0.02, k2=0.02
-
Skrypt: vignette 
Suwak winieta_value ("Siła") - do usunięcia 
Ustawienia na stronie, Tylko przełącznik on/off. Jeśli włączone, stosuje domyślny filtr vignette.
-
Skrypt: fade, type='in', start_frame=0, nb_frames=30 (rozjaśnianie przez 30 klatek na początku)
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-300 co 10
Domyślna wartośc na stronie 30 odpowiadajaca fade, type='in', start_frame=0, nb_frames=30
-
Skrypt: fade, type='out', start_frame=300, nb_frames=30 (ściemnianie przez 30 klatek, start_frame wymaga dynamicznego obliczenia)
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-300 co 10
Domyślna wartośc na stronie 30 odpowiadajaca nb_frames=30
Mapowanie: Włącza/wyłącza efekt. start_frame obliczane dynamicznie (np. całkowita_liczba_klatek_wideo - nb_frames_fade_out).
-
Skrypt: hqdn3d=1.5:1.5:6:6 (luma_spatial:chroma_spatial:luma_tmp:chroma_tmp)
Suwak - do usunięcia 
Ustawienia na stronie, Tylko przełącznik on/off. Jeśli włączone, stosuje domyslnie hqdn3d=1.5:1.5:6:6 (luma_spatial:chroma_spatial:luma_tmp:chroma_tmp)
-
Skrypt: aevalsrc=exprs=0|0:d=1.5..., atrim, start=1.5, concat (sekwencja przygotowawcza audio)
Ustawienia na stronie wyświetlane w normalnych liczbach, zakres 0-15 co 0.5
Domyślna wartośc na stronie 1.5 odpowiadajaca dodanie 1.5 ciszy na poczatku. WAŻNE PAMIETAJMY O TYM ZEBY PASOWALO DO RESZTY SKRYPTU I PRZETWARZANIA NA PODSTAWIE ILE CISZY CHCEMY.
-
Skrypt: asetrate, '44100*1.03' (przyspieszenie audio o 1.03x)
Ustawienia na stronie wyświetlanie w % zakres 0-30
Domyślnie 3% odpowiadajace asetrate, '44100*1.03' (przyspieszenie audio o 1.03x)