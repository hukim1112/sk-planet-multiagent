"""
API Key 암호화 도구
===================
이 스크립트는 API Key 등의 민감 정보를 AES-256-GCM으로 암호화하여,
GitHub Pages의 index.html에 안전하게 삽입할 수 있는 base64 문자열을 생성합니다.

사용법:
    1. keys.txt 파일에 암호화할 내용을 작성합니다.
    2. 이 스크립트를 실행합니다: python encrypt_keys.py
    3. 패스워드를 입력합니다.
    4. 출력된 base64 문자열을 index.html의 ENCRYPTED_DATA 변수에 붙여넣습니다.

    다른 파일을 지정하려면: python encrypt_keys.py myfile.txt

필요 패키지:
    pip install cryptography
"""

import os
import sys
import hashlib
import base64
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(password: str, plaintext: str) -> str:
    """
    PBKDF2-SHA256 키 파생 + AES-256-GCM 암호화.
    반환값: base64(salt[16] + iv[12] + ciphertext + tag[16])
    
    JavaScript Web Crypto API와 동일한 파라미터를 사용하여 호환됩니다.
    """
    salt = os.urandom(16)
    iv = os.urandom(12)
    
    # PBKDF2로 패스워드에서 256-bit 키 유도
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100_000, dklen=32)
    
    # AES-256-GCM 암호화 (ciphertext + 16-byte auth tag 포함)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode('utf-8'), None)
    
    # salt + iv + ciphertext(+tag) 를 하나로 합쳐 base64 인코딩
    packed = salt + iv + ciphertext_with_tag
    return base64.b64encode(packed).decode('ascii')


def main():
    print("=" * 60)
    print("  🔐 API Key 암호화 도구")
    print("=" * 60)
    print()

    # 파일 경로 결정 (인자가 있으면 사용, 없으면 기본값 keys.txt)
    filepath = sys.argv[1] if len(sys.argv) > 1 else "keys.txt"

    if not os.path.exists(filepath):
        print(f"❌ 파일을 찾을 수 없습니다: {filepath}")
        print()
        print("사용법:")
        print(f"  1. '{filepath}' 파일을 만들고 암호화할 내용을 작성하세요.")
        print("     예시 내용:")
        print("       OPENAI_API_KEY=sk-proj-xxxx")
        print("       LANGSMITH_API_KEY=lsv2_xxxx")
        print()
        print("  2. 다시 실행하세요: python encrypt_keys.py")
        return

    with open(filepath, 'r', encoding='utf-8') as f:
        plaintext = f.read()

    if not plaintext.strip():
        print(f"❌ 파일이 비어있습니다: {filepath}")
        return

    print(f"📄 파일 읽기 완료: {filepath} ({len(plaintext)}자)")
    print()

    # 패스워드 입력 (화면에 표시되지 않음)
    password = getpass.getpass("암호화에 사용할 패스워드를 입력하세요: ")
    if not password:
        print("❌ 패스워드가 비어있습니다.")
        return
    
    password_confirm = getpass.getpass("패스워드를 다시 한번 입력하세요: ")
    if password != password_confirm:
        print("❌ 패스워드가 일치하지 않습니다.")
        return

    # 암호화 수행
    encrypted = encrypt(password, plaintext)
    
    print()
    print("=" * 60)
    print("  ✅ 암호화 완료!")
    print("=" * 60)
    print()
    print("아래 문자열을 index.html의 ENCRYPTED_DATA 변수에 붙여넣으세요:")
    print()
    print(encrypted)
    print()
    print(f"(원문 길이: {len(plaintext)}자 → 암호문 길이: {len(encrypted)}자)")
    print()
    print(f"⚠️  작업이 끝나면 '{filepath}' 파일을 삭제하세요! (평문 API Key 보호)")


if __name__ == "__main__":
    main()
