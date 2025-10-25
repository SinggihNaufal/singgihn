import streamlit as st
import os
import hashlib
import numpy as np
from PIL import Image
from io import BytesIO
import secrets

# =================================================================
# 1. Fungsi Kriptografi Inti
# =================================================================


# --- Vigenère Cipher untuk Teks ---
def vigenere_encrypt(plaintext, key):
    """Enkripsi teks menggunakan Vigenère Cipher."""
    ciphertext = []
    key = key.upper()
    key_len = len(key)
    key_index = 0
    for char in plaintext:
        if "a" <= char <= "z":
            shift = ord(key[key_index % key_len]) - ord("A")
            encrypted_char = chr(((ord(char) - ord("a") + shift) % 26) + ord("a"))
            key_index += 1
        elif "A" <= char <= "Z":
            shift = ord(key[key_index % key_len]) - ord("A")
            encrypted_char = chr(((ord(char) - ord("A") + shift) % 26) + ord("A"))
            key_index += 1
        else:
            encrypted_char = char
        ciphertext.append(encrypted_char)
    return "".join(ciphertext)


def vigenere_decrypt(ciphertext, key):
    """Dekripsi teks menggunakan Vigenère Cipher."""
    plaintext = []
    key = key.upper()
    key_len = len(key)
    key_index = 0
    for char in ciphertext:
        if "a" <= char <= "z":
            shift = ord(key[key_index % key_len]) - ord("A")
            decrypted_char = chr(((ord(char) - ord("a") - shift) % 26) + ord("a"))
            key_index += 1
        elif "A" <= char <= "Z":
            shift = ord(key[key_index % key_len]) - ord("A")
            decrypted_char = chr(((ord(char) - ord("A") - shift) % 26) + ord("A"))
            key_index += 1
        else:
            decrypted_char = char
        plaintext.append(decrypted_char)
    return "".join(plaintext)


# --- One-Time Pad (OTP) untuk Gambar/Video/File ---
def generate_otp_key(data_size):
    """Menghasilkan kunci acak (bytes) seukuran data menggunakan sumber randomness kriptografis."""
    return secrets.token_bytes(data_size)


def otp_operation(data, key):
    """Melakukan operasi XOR untuk enkripsi/dekripsi OTP."""
    data_array = np.frombuffer(data, dtype=np.uint8)
    key_array = np.frombuffer(key, dtype=np.uint8)

    if data_array.size != key_array.size:
        raise ValueError("Ukuran data dan kunci harus sama untuk OTP.")

    return np.bitwise_xor(data_array, key_array).tobytes()


# --- Verifikasi SHA-256 ---
def get_data_sha256(data):
    """Menghitung hash SHA-256 dari data (bytes)."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


# =================================================================
# 2. Komponen UI Minimalis
# =================================================================


def create_section_header(title, description):
    """Header section yang minimalis"""
    st.markdown(f"### {title}")
    st.caption(description)
    st.divider()


def create_file_uploader(label, file_types, key):
    """File uploader yang konsisten"""
    return st.file_uploader(label, type=file_types, key=key)


# =================================================================
# 3. Logika Aplikasi - Tampilan Minimalis & Konsisten
# =================================================================


def vigenere_section():
    """Bagian Vigenère Cipher dengan tampilan minimalis"""

    # Mode Selection
    operation_mode = st.radio(
        "Pilih Operasi:",
        ["🔒 Enkripsi Teks", "🔓 Dekripsi Teks"],
        horizontal=True,
        key="vigenere_radio_mode",
    )

    st.divider()

    # Input Area
    col1, col2 = st.columns([2, 1])

    with col1:
        text_input = st.text_area(
            "Teks:",
            height=120,
            placeholder="Masukkan teks di sini...",
            help="Plaintext untuk enkripsi atau ciphertext untuk dekripsi",
            key="vigenere_text_input",
        )

    with col2:
        key_input = st.text_input(
            "Kunci:",
            placeholder="Masukkan kunci...",
            help="Kunci untuk enkripsi/dekripsi (hanya alfabet)",
            key="vigenere_key_input",
        )

    # Action Button
    if st.button(
        (
            "🚀 Proses Sekarang"
            if operation_mode == "🔒 Enkripsi Teks"
            else "🔓 Proses Sekarang"
        ),
        use_container_width=True,
        type="primary",
        key="vigenere_process_btn",
    ):
        if not text_input or not key_input:
            st.error("❌ Teks dan kunci harus diisi")
            return

        # Validasi kunci hanya alfabet
        if not key_input.replace(" ", "").isalpha():
            st.error("❌ Kunci hanya boleh mengandung huruf alfabet (A-Z, a-z)")
            return

        try:
            if operation_mode == "🔒 Enkripsi Teks":
                result = vigenere_encrypt(text_input, key_input)
                mode = "terenkripsi"
            else:
                result = vigenere_decrypt(text_input, key_input)
                mode = "terdekripsi"

            st.session_state["vigenere_result"] = result
            st.session_state["vigenere_mode"] = mode
            st.success(f"✅ {operation_mode} berhasil!")

        except Exception as e:
            st.error(f"❌ Gagal: {e}")

    # Results Section
    if st.session_state.get("vigenere_result"):
        st.divider()
        result = st.session_state["vigenere_result"]
        mode = st.session_state["vigenere_mode"]

        st.text_area(
            f"Hasil Teks {mode.capitalize()}:",
            result,
            height=120,
            key="vigenere_result_display",
        )

        file_name = f"teks_{mode}.txt"
        st.download_button(
            label="📥 Unduh Hasil",
            data=result.encode("utf-8"),
            file_name=file_name,
            mime="text/plain",
            use_container_width=True,
            key="vigenere_download_btn",
        )


def otp_section():
    """Bagian One-Time Pad dengan tampilan minimalis"""

    # Tambahan: Pemilihan Media Type
    media_type = st.radio(
        "Pilih Tipe Media:",
        ["🖼️ Gambar (JPG/PNG)", "🎬 Video/File Biner"],
        horizontal=True,
        key="otp_media_type",
    )

    st.divider()

    # Mode Selection (Enkripsi/Dekripsi)
    operation_mode = st.radio(
        "Pilih Operasi:",
        ["🔒 Enkripsi File", "🔓 Dekripsi File"],
        horizontal=True,
        key="otp_radio_mode",
    )

    st.divider()

    if operation_mode == "🔒 Enkripsi File":
        otp_encryption_section(media_type)
    else:
        otp_decryption_section(media_type)


def otp_encryption_section(media_type):
    """Section enkripsi OTP yang minimalis"""

    is_image = media_type == "🖼️ Gambar (JPG/PNG)"

    if is_image:
        file_types = ["png", "jpg", "jpeg"]
        label = "Pilih gambar untuk dienkripsi:"
        st.info(
            "💡 Gambar akan dikonversi ke format PNG/RGB/Grayscale untuk konsistensi."
        )
    else:
        file_types = ["mp4", "avi", "mov", "mkv", "wmv", "flv", "pdf", "zip", "bin"]
        label = "Pilih file video/biner untuk dienkripsi:"

    uploaded_file = create_file_uploader(
        label,
        file_types,
        "otp_enc_file_uploader",
    )

    if uploaded_file:
        file_bytes = uploaded_file.getvalue()
        width, height, channels = 0, 0, 1

        if is_image:
            try:
                image = Image.open(uploaded_file)

                # Konversi ke format standar
                if image.mode == "L":
                    channels = 1
                elif image.mode != "RGB":
                    image = image.convert("RGB")
                    channels = 3
                else:
                    channels = 3

                img_array = np.array(image)

                if len(img_array.shape) == 3:
                    height, width, _ = img_array.shape
                elif len(img_array.shape) == 2:
                    height, width = img_array.shape
                    channels = 1

                file_bytes = img_array.tobytes()

                if channels not in [1, 3]:
                    st.error(f"❌ Format gambar tidak didukung. Channels: {channels}")
                    return

                st.image(
                    image,
                    caption=f"Preview: {uploaded_file.name} ({width}×{height}, {channels} channel)",
                    use_column_width=True,
                )

            except Exception as e:
                st.error(f"❌ Error memproses gambar: {e}")
                return
        else:
            # Untuk video/file biner
            st.write(f"**Ukuran File:** {len(file_bytes):,} bytes")

        # Regenerate key jika file baru / dims berubah
        current_dims = (width, height, channels)
        if (
            st.session_state.get("otp_enc_file_name") != uploaded_file.name
            or st.session_state.get("otp_enc_img_dims") != current_dims
        ):
            st.session_state.otp_enc_key = generate_otp_key(len(file_bytes))
            st.session_state.otp_enc_file_name = uploaded_file.name
            st.session_state.otp_enc_img_dims = current_dims
            st.session_state.otp_enc_file_bytes = file_bytes
            st.session_state.otp_enc_result = None

        # Encryption Button
        if st.button(
            f"🔒 Enkripsi {'Gambar' if is_image else 'File'}",
            use_container_width=True,
            type="primary",
            key="otp_encrypt_btn",
        ):
            try:
                encrypted_data = otp_operation(file_bytes, st.session_state.otp_enc_key)

                base_name = os.path.splitext(uploaded_file.name)[0]

                # Buat header metadata
                header = (
                    width.to_bytes(4, "big")
                    + height.to_bytes(4, "big")
                    + channels.to_bytes(4, "big")
                )

                packaged_encrypted = header + encrypted_data

                st.session_state["otp_enc_result"] = {
                    "data": packaged_encrypted,
                    "name": f"{base_name}_encrypted.bin",
                    "key": st.session_state.otp_enc_key,
                    "key_name": f"{base_name}_key.bin",
                    "metadata": {
                        "width": width,
                        "height": height,
                        "channels": channels,
                        "is_image": is_image,
                        "original_ext": os.path.splitext(uploaded_file.name)[1],
                    },
                }

                st.success(f"✅ Enkripsi berhasil!")

            except Exception as e:
                st.error(f"❌ Gagal enkripsi: {e}")

        # Download Results
        if st.session_state.get("otp_enc_result"):
            st.divider()
            result = st.session_state.otp_enc_result

            st.info("💡 Simpan kedua file untuk dekripsi nanti:")
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="📥 Data Terenkripsi",
                    data=result["data"],
                    file_name=result["name"],
                    mime="application/octet-stream",
                    use_container_width=True,
                    key="otp_download_encrypted",
                )

            with col2:
                st.download_button(
                    label="🔑 Kunci OTP",
                    data=result["key"],
                    file_name=result["key_name"],
                    mime="application/octet-stream",
                    use_container_width=True,
                    key="otp_download_key",
                )

            with st.expander("📊 Detail Enkripsi"):
                st.write(
                    f"**Tipe:** {'Gambar' if result['metadata']['is_image'] else 'File Biner'}"
                )
                if result["metadata"]["is_image"]:
                    st.write(f"**Dimensi:** {width} × {height}")
                    st.write(f"**Channels:** {channels}")
                st.write(f"**Ekstensi Asli:** {result['metadata']['original_ext']}")
                st.write(f"**Ukuran File:** {len(result['data']):,} bytes")
                st.write(f"**Ukuran Kunci:** {len(result['key']):,} bytes")
    else:
        st.info("📁 Unggah file untuk memulai enkripsi")


def get_mime_type(ext):
    """Fungsi sederhana untuk mendapatkan MIME type dari ekstensi"""
    ext = ext.lower().strip(".")
    mime_map = {
        "mp4": "video/mp4",
        "mov": "video/quicktime",
        "avi": "video/x-msvideo",
        "mkv": "video/x-matroska",
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "pdf": "application/pdf",
        "zip": "application/zip",
    }
    return mime_map.get(ext, "application/octet-stream")


def otp_decryption_section(media_type):
    """Section dekripsi OTP yang minimalis"""

    is_image_mode = media_type == "🖼️ Gambar (JPG/PNG)"

    col1, col2 = st.columns(2)

    with col1:
        uploaded_bin = create_file_uploader(
            "File terenkripsi (.bin):", ["bin"], "otp_dec_bin_uploader"
        )

    with col2:
        uploaded_key = create_file_uploader(
            "Kunci OTP (.bin):", ["bin"], "otp_dec_key_uploader"
        )

    # Input ekstensi asli hanya untuk non-gambar
    if not is_image_mode:
        ext_input = st.text_input(
            "Ekstensi File Asli:",
            value="mp4",
            placeholder="mp4, avi, pdf, dll.",
            help="Diperlukan untuk file non-gambar",
            key="otp_dec_ext_input",
        )
    else:
        ext_input = ""

    if uploaded_bin and uploaded_key:
        bin_bytes = uploaded_bin.getvalue()
        key_bytes = uploaded_key.getvalue()

        # Validasi file terenkripsi
        if len(bin_bytes) <= 12:
            st.error("❌ File terenkripsi tidak valid (terlalu kecil).")
            return

        # Baca header metadata
        try:
            header = bin_bytes[:12]
            width = int.from_bytes(header[0:4], "big")
            height = int.from_bytes(header[4:8], "big")
            channels = int.from_bytes(header[8:12], "big")

            # Deteksi tipe file berdasarkan metadata
            is_file_image = width > 0 and height > 0 and channels in [1, 3]

            # Auto-koreksi mode jika tidak match
            if is_file_image and not is_image_mode:
                st.info("🔍 Terdeteksi file gambar berdasarkan metadata")
                is_image = True
            elif not is_file_image and is_image_mode:
                st.info("🔍 Terdeteksi file biner berdasarkan metadata")
                is_image = False
                if not ext_input:
                    st.error("❌ Harap masukkan ekstensi file asli")
                    return
            else:
                is_image = is_image_mode

        except Exception as e:
            st.error(f"❌ Gagal membaca metadata: {e}")
            return

        encrypted_data = bin_bytes[12:]
        data_size = len(encrypted_data)

        # Validasi ukuran kunci
        if data_size != len(key_bytes):
            st.error("❌ Ukuran file dan kunci tidak cocok.")
            return

        # Tampilkan info file
        st.success(f"✅ File valid - {data_size:,} bytes data terenkripsi")

        # Dekripsi Button
        if st.button(
            "🔓 Dekripsi File",
            use_container_width=True,
            type="primary",
            key="otp_decrypt_btn",
        ):
            if not is_image and not ext_input:
                st.error("❌ Harap masukkan ekstensi file asli")
                return

            try:
                decrypted_bytes = otp_operation(encrypted_data, key_bytes)
                base_name = os.path.splitext(uploaded_bin.name)[0].replace(
                    "_encrypted", ""
                )

                final_download_data = None
                output_mime = None
                output_ext = None

                # --- Logika Rekonstruksi Gambar ---
                if is_image:
                    # Validasi ukuran data gambar
                    expected_size = height * width * channels
                    if len(decrypted_bytes) != expected_size:
                        st.error(
                            f"❌ Ukuran data tidak sesuai: expected {expected_size}, got {len(decrypted_bytes)}"
                        )
                        return

                    output_ext = ".png"
                    output_mime = "image/png"

                    # Rekonstruksi gambar
                    if channels == 3:
                        decrypted_array = np.frombuffer(
                            decrypted_bytes, dtype=np.uint8
                        ).reshape((height, width, 3))
                        decrypted_img = Image.fromarray(decrypted_array, "RGB")
                    else:  # channels == 1
                        decrypted_array = np.frombuffer(
                            decrypted_bytes, dtype=np.uint8
                        ).reshape((height, width))
                        decrypted_img = Image.fromarray(decrypted_array, "L")

                    # Tampilkan dan simpan gambar
                    st.image(
                        decrypted_img,
                        caption=f"Gambar Hasil Dekripsi ({width}×{height})",
                        use_column_width=True,
                    )

                    buf = BytesIO()
                    decrypted_img.save(buf, format="PNG")
                    final_download_data = buf.getvalue()

                # --- Logika File Biner ---
                else:
                    clean_ext = ext_input.strip().lower()
                    if not clean_ext.startswith("."):
                        clean_ext = "." + clean_ext

                    output_ext = clean_ext
                    output_mime = get_mime_type(clean_ext)
                    final_download_data = decrypted_bytes

                    st.success(f"✅ File {output_ext.upper()} berhasil didekripsi")
                    st.info("💡 File biner siap diunduh")

                output_name = f"{base_name}_decrypted{output_ext}"

                # Download button
                st.download_button(
                    label=f"📥 Unduh File {'Gambar' if is_image else output_ext.upper()}",
                    data=final_download_data,
                    file_name=output_name,
                    mime=output_mime,
                    use_container_width=True,
                    key="otp_download_decrypted_file",
                )

            except Exception as e:
                st.error(f"❌ Gagal dekripsi: {e}")

    else:
        st.info("📁 Unggah file terenkripsi dan kunci OTP")


# =================================================================
# 4. Main Application
# =================================================================


def main():
    # Konfigurasi halaman minimalis
    st.set_page_config(
        page_title="Kriptografi Tool",
        page_icon="🔐",
        layout="centered",
        initial_sidebar_state="collapsed",
    )

    # Custom CSS minimalis
    st.markdown(
        """
        <style>
        .main-title {
            text-align: center;
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
            color: #1f77b4;
        }
        .main-subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 2rem;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 1rem;
        }
        .stTabs [data-baseweb="tab"] {
            padding: 1rem 2rem;
            border-radius: 8px 8px 0 0;
        }
        </style>
    """,
        unsafe_allow_html=True,
    )

    # Header minimalis
    st.markdown('<p class="main-title">🔐 Kriptografi Tool</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="main-subtitle">Enkripsi & Dekripsi yang Sederhana dan Aman</p>',
        unsafe_allow_html=True,
    )

    # Tabs utama
    tab1, tab2 = st.tabs(["✍️ VIGENÈRE CIPHER", "🖼️ ONE-TIME PAD"])

    with tab1:
        create_section_header(
            "Vigenère Cipher", "Enkripsi dan dekripsi teks dengan algoritma klasik"
        )
        vigenere_section()

    with tab2:
        create_section_header(
            "One-Time Pad",
            "Enkripsi dan dekripsi gambar/video/file biner dengan keamanan sempurna",
        )
        otp_section()

    # Footer minimalis
    st.divider()
    st.caption("🔒 Kriptografi Tool - Keamanan Digital Terdepan")


# Inisialisasi Session State
if __name__ == "__main__":
    # State untuk Vigenere
    if "vigenere_result" not in st.session_state:
        st.session_state.vigenere_result = None
    if "vigenere_mode" not in st.session_state:
        st.session_state.vigenere_mode = None

    # State untuk OTP Enkripsi
    if "otp_enc_key" not in st.session_state:
        st.session_state.otp_enc_key = None
    if "otp_enc_file_name" not in st.session_state:
        st.session_state.otp_enc_file_name = ""
    if "otp_enc_img_dims" not in st.session_state:
        st.session_state.otp_enc_img_dims = None
    if "otp_enc_file_bytes" not in st.session_state:
        st.session_state.otp_enc_file_bytes = None
    if "otp_enc_result" not in st.session_state:
        st.session_state.otp_enc_result = None

    # State untuk OTP Dekripsi
    if "otp_dec_result" not in st.session_state:
        st.session_state.otp_dec_result = None

    main()
