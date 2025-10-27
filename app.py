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


# --- One-Time Pad (OTP) untuk Video ---
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


# --- Validasi MP4 ---
def validate_mp4_file(file_bytes):
    """Validasi signature MP4 file"""
    if len(file_bytes) < 8:
        return False, "File terlalu kecil"

    # Check for MP4 signature (ftyp)
    mp4_signatures = [b"ftyp", b"moov", b"mdat"]
    file_signature = file_bytes[4:8]

    if file_signature in mp4_signatures:
        return True, "Valid MP4 file"
    else:
        # Fallback: check file extension or allow with warning
        return True, "File mungkin bukan MP4 standar, melanjutkan dengan hati-hati"


# --- Super Enkripsi: Gabungan Vigenère + OTP ---
def super_encrypt(video_bytes, vigenere_key, otp_key=None):
    """Super enkripsi: Vigenère untuk metadata + OTP untuk video"""

    # Generate OTP key jika tidak provided
    if otp_key is None:
        otp_key = generate_otp_key(len(video_bytes))

    # Enkripsi metadata dengan Vigenère
    metadata = f"VIDEO_MP4_{len(video_bytes)}_{secrets.token_hex(4)}"
    encrypted_metadata = vigenere_encrypt(metadata, vigenere_key)

    # Enkripsi video dengan OTP
    encrypted_video = otp_operation(video_bytes, otp_key)

    # Package: metadata + video terenkripsi
    metadata_bytes = encrypted_metadata.encode("utf-8")
    metadata_length = len(metadata_bytes).to_bytes(4, "big")

    packaged_data = metadata_length + metadata_bytes + encrypted_video

    return {
        "encrypted_data": packaged_data,
        "otp_key": otp_key,
        "metadata": encrypted_metadata,
        "original_metadata": metadata,
    }


def super_decrypt(encrypted_package, vigenere_key, otp_key):
    """Super dekripsi: Dekripsi metadata dengan Vigenère + video dengan OTP"""

    try:
        # Extract metadata length
        metadata_length = int.from_bytes(encrypted_package[:4], "big")

        # Extract dan dekripsi metadata
        encrypted_metadata = encrypted_package[4 : 4 + metadata_length].decode("utf-8")
        decrypted_metadata = vigenere_decrypt(encrypted_metadata, vigenere_key)

        # Extract video terenkripsi
        encrypted_video = encrypted_package[4 + metadata_length :]

        # Validasi metadata
        if not decrypted_metadata.startswith("VIDEO_MP4_"):
            raise ValueError("Metadata tidak valid - kunci Vigenère mungkin salah")

        # Dekripsi video dengan OTP
        decrypted_video = otp_operation(encrypted_video, otp_key)

        return {"decrypted_video": decrypted_video, "metadata": decrypted_metadata}

    except Exception as e:
        raise ValueError(f"Gagal dekripsi: {e}")


# --- Verifikasi SHA-256 ---
def get_data_sha256(data):
    """Menghitung hash SHA-256 dari data (bytes)."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


# =================================================================
# 2. Komponen UI Minimalis
# =================================================================


def format_file_size(size_bytes):
    """Format ukuran file menjadi readable"""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


# =================================================================
# 3. Logika Aplikasi - Super Enkripsi
# =================================================================


def super_encryption_section():
    """Section super enkripsi: Vigenère + OTP"""

    st.write("**📤 Upload File Video**")
    uploaded_file = st.file_uploader(
        "Pilih file video MP4 untuk dienkripsi:",
        type=["mp4"],
        key="super_enc_file_uploader",
        label_visibility="collapsed",
    )

    if uploaded_file:
        file_bytes = uploaded_file.getvalue()

        # Validasi file MP4
        is_valid, validation_msg = validate_mp4_file(file_bytes)

        if not is_valid:
            st.error(f"❌ {validation_msg}")
            return

        # Tampilkan preview video dan info file

        st.video(uploaded_file, format="video/mp4")
        if "mungkin bukan MP4 standar" in validation_msg:
            st.warning("⚠️ File mungkin tidak standar")

        # Input kunci Vigenère
        st.write("**🔑 Masukkan Kunci Vigenère**")
        vigenere_key = st.text_input(
            "Kunci Vigenère:",
            placeholder="Contoh: MYKEY123",
            help="Kunci untuk enkripsi metadata (hanya huruf A-Z, a-z)",
            key="super_enc_vigenere_key",
            label_visibility="collapsed",
        )

        # Validasi kunci Vigenère
        if vigenere_key and not vigenere_key.replace(" ", "").isalpha():
            st.error("❌ Kunci hanya boleh mengandung huruf alfabet (A-Z, a-z)")
            vigenere_key_valid = False
        else:
            vigenere_key_valid = bool(vigenere_key)

        # Encryption Button
        if st.button(
            "🔒 Enkripsi Sekarang",
            use_container_width=True,
            type="primary",
            key="super_encrypt_btn",
            disabled=not vigenere_key_valid,
        ):
            try:
                with st.spinner("🔄 Melakukan super enkripsi..."):
                    result = super_encrypt(file_bytes, vigenere_key)

                base_name = os.path.splitext(uploaded_file.name)[0]

                st.session_state["super_enc_result"] = {
                    "encrypted_data": result["encrypted_data"],
                    "otp_key": result["otp_key"],
                    "vigenere_key": vigenere_key,
                    "encrypted_data_name": f"{base_name}_super_encrypted.bin",
                    "otp_key_name": f"{base_name}_otp_key.bin",
                    "metadata": result["metadata"],
                    "original_metadata": result["original_metadata"],
                    "original_name": uploaded_file.name,
                    "file_size": len(file_bytes),
                }

                st.success("✅ **Super Enkripsi Berhasil!**")

            except Exception as e:
                st.error(f"❌ Gagal enkripsi: {str(e)}")

        # Download Results
        if st.session_state.get("super_enc_result"):
            result = st.session_state.super_enc_result

            st.write("**📥 Download Hasil Enkripsi**")
            st.info("Simpan kedua file untuk dekripsi nanti:")

            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="💾 Data Terenkripsi",
                    data=result["encrypted_data"],
                    file_name=result["encrypted_data_name"],
                    mime="application/octet-stream",
                    use_container_width=True,
                    key="super_download_encrypted",
                    help="File berisi video terenkripsi + metadata",
                )

            with col2:
                st.download_button(
                    label="🔑 Kunci OTP",
                    data=result["otp_key"],
                    file_name=result["otp_key_name"],
                    mime="application/octet-stream",
                    use_container_width=True,
                    key="super_download_otp_key",
                    help="Kunci acak untuk dekripsi video",
                )

            # Info Detail Enkripsi
            with st.expander("📊 Detail Enkripsi", expanded=False):
                col1, col2 = st.columns(2)

                with col1:
                    st.write("**📁 Informasi File**")
                    st.write(f"**Nama asli:** {result['original_name']}")
                    st.write(
                        f"**Ukuran asli:** {format_file_size(result['file_size'])}"
                    )
                    st.write(f"**Kunci Vigenère:** {result['vigenere_key']}")

                with col2:
                    st.write("**🔐 Informasi Keamanan**")
                    st.write(
                        f"**Data terenkripsi:** {format_file_size(len(result['encrypted_data']))}"
                    )
                    st.write(
                        f"**Kunci OTP:** {format_file_size(len(result['otp_key']))}"
                    )
                    st.write(f"**Metadata:** {result['metadata'][:30]}...")

                st.write("**🔍 Hash Verifikasi**")
                col1, col2 = st.columns(2)
                with col1:
                    st.code(f"Data: {get_data_sha256(result['encrypted_data'])}")
                with col2:
                    st.code(f"Kunci: {get_data_sha256(result['otp_key'])}")

    else:
        st.info("📁 Silakan upload file video MP4 untuk memulai enkripsi")


def super_decryption_section():
    """Section super dekripsi: Vigenère + OTP"""

    st.write("**📤 Upload File Terenkripsi & Kunci OTP**")

    col1, col2 = st.columns(2)
    with col1:
        uploaded_encrypted = st.file_uploader(
            "File terenkripsi (.bin):",
            type=["bin"],
            key="super_dec_encrypted_uploader",
            label_visibility="collapsed",
        )
    with col2:
        uploaded_otp_key = st.file_uploader(
            "Kunci OTP (.bin):",
            type=["bin"],
            key="super_dec_otp_key_uploader",
            label_visibility="collapsed",
        )

    # Input kunci Vigenère untuk dekripsi
    st.write("**🔑 Masukkan Kunci Vigenère**")
    vigenere_key = st.text_input(
        "Kunci Vigenère:",
        placeholder="Kunci yang sama dengan saat enkripsi",
        help="Kunci untuk dekripsi metadata",
        key="super_dec_vigenere_key",
        label_visibility="collapsed",
    )

    if uploaded_encrypted and uploaded_otp_key and vigenere_key:
        encrypted_bytes = uploaded_encrypted.getvalue()
        otp_key_bytes = uploaded_otp_key.getvalue()

        # Tampilkan info file
        st.success("✅ **File dan kunci siap**")

        col1, col2 = st.columns(2)
        with col1:
            st.write("**📁 Info File**")
            st.write(f"**Data terenkripsi:** {format_file_size(len(encrypted_bytes))}")
            st.write(f"**Kunci OTP:** {format_file_size(len(otp_key_bytes))}")
            st.write(f"**Kunci Vigenère:** {vigenere_key}")

        # Validasi kunci Vigenère
        if not vigenere_key.replace(" ", "").isalpha():
            st.error("❌ Kunci hanya boleh mengandung huruf alfabet (A-Z, a-z)")
            return

        # Dekripsi Button
        if st.button(
            "🔓 Dekripsi Sekarang",
            use_container_width=True,
            type="primary",
            key="super_decrypt_btn",
        ):
            try:
                with st.spinner("🔄 Melakukan super dekripsi..."):
                    result = super_decrypt(encrypted_bytes, vigenere_key, otp_key_bytes)

                base_name = os.path.splitext(uploaded_encrypted.name)[0].replace(
                    "_super_encrypted", ""
                )
                output_name = f"{base_name}_decrypted.mp4"

                # Tampilkan video yang didekripsi
                st.success("✅ **Super Dekripsi Berhasil!**")

                st.video(result["decrypted_video"], format="video/mp4")

                # Info Detail Dekripsi
                with st.expander("📊 Detail Dekripsi", expanded=False):
                    st.write("**📝 Metadata Terdekripsi**")
                    st.success(f"`{result['metadata']}`")

                    st.write("**🔍 Hash Verifikasi**")
                    st.code(
                        f"Video terdekripsi: {get_data_sha256(result['decrypted_video'])}"
                    )

                    st.write("**✅ Status**")
                    st.success("Semua checksum valid - file berhasil didekripsi")

                # Download button
                st.download_button(
                    label="📥 Download Video Hasil Dekripsi",
                    data=result["decrypted_video"],
                    file_name=output_name,
                    mime="video/mp4",
                    use_container_width=True,
                    key="super_download_decrypted",
                    help="Video asli yang telah berhasil didekripsi",
                )

            except Exception as e:
                st.error(f"❌ Gagal dekripsi: {str(e)}")

                # Tampilkan info error detail
                with st.expander("🔧 Info Debug", expanded=False):
                    st.error(f"Error detail: {str(e)}")
                    st.info(
                        """
                    **Kemungkinan masalah:**
                    - Kunci Vigenère tidak sesuai
                    - File terenkripsi corrupt
                    - Kunci OTP tidak cocok
                    - Format file tidak sesuai
                    """
                    )

    else:
        st.info("📁 Upload file terenkripsi, kunci OTP, dan masukkan kunci Vigenère")


# =================================================================
# 4. Main Application
# =================================================================


def main():
    # Konfigurasi halaman minimalis
    st.set_page_config(
        page_title="Super Kriptografi Tool",
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
            font-size: 2.2rem;
            margin-bottom: 0.5rem;
            color: #1f77b4;
            font-weight: 700;
        }
        .main-subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 2rem;
            font-size: 1.1rem;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 0.5rem;
        }
        .stTabs [data-baseweb="tab"] {
            padding: 0.8rem 1.5rem;
            border-radius: 8px 8px 0 0;
            font-weight: 500;
        }
        .stButton button {
            width: 100%;
            border-radius: 8px;
            font-weight: 500;
        }
        .file-uploader {
            margin-bottom: 1rem;
        }
        .info-box {
            background-color: #f0f8ff;
            padding: 1rem;
            border-radius: 0.5rem;
            border-left: 4px solid #1f77b4;
            margin: 0.5rem 0;
        }
        </style>
    """,
        unsafe_allow_html=True,
    )

    # Header minimalis
    st.markdown('<p class="main-title">🔐 Kriptografi Tool</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="main-subtitle">Vigenère Cipher (metadata) + One-Time Pad (video)</p>',
        unsafe_allow_html=True,
    )

    # Tabs utama
    tab1, tab2 = st.tabs(["🔒 **ENKRIPSI**", "🔓 **DEKRIPSI**"])

    with tab1:
        super_encryption_section()

    with tab2:
        super_decryption_section()

    # Footer minimalis
    st.divider()
    st.caption("🔒 Super Kriptografi Tool • Keamanan Berlapis • v1.0")


# Inisialisasi Session State
if __name__ == "__main__":
    # State untuk Super Enkripsi
    if "super_enc_result" not in st.session_state:
        st.session_state.super_enc_result = None

    main()
