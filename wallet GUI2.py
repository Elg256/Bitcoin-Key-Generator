import sys
from PyQt5.QtWidgets import QApplication, QDialog, QTextEdit,QMainWindow ,QWidget, QLabel, QLineEdit, QPushButton, QGridLayout, QVBoxLayout, QMenuBar, QMenu, QAction
from PyQt5 import QtWidgets , QtCore

import hashlib
import base58
import ecdsa
from Crypto.Hash import RIPEMD160

import bech32
import os


class ImportPrivateKeyWindow(QDialog):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window  # Référence à l'instance de MainWindow
        self.setWindowTitle('Import Private Key')
        self.setGeometry(200, 200, 350, 200)

        self.label = QLabel('Enter an integer to determine the Bitcoin private key:', self)
        self.label.setGeometry(10, 50, 400, 20)

        self.input_field = QLineEdit(self)
        self.input_field.setGeometry(25, 70, 200, 20)

        self.ok_button = QPushButton('Ok', self)
        self.ok_button.setGeometry(25, 100, 200, 30)

        self.ok_button.clicked.connect(self.take_user_input)



    def take_user_input(self):
        user_input = self.input_field.text()
        # Utilisez la méthode de generate_key_and_addresses de MainWindow avec la référence
        self.main_window.generate_key_and_addresses(user_input)
        self.accept()


class MainWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Bitcoin Key Generator')
        self.setGeometry(100, 100, 700, 500)

        # Création de la barre de menu
        bar = self.menuBar()
        # Menu Fichier
        file_menu = bar.addMenu('File')



        close_action = QAction('Close', self)

        file_menu.addAction(close_action)
        close_action.triggered.connect(self.close)

        # Menu Edition
        edit_menu = bar.addMenu('About')
        undo_action = QAction('Version 0.1', self)
        redo_action = QAction('By Elg256', self)
        edit_menu.addAction(undo_action)
        edit_menu.addAction(redo_action)

        self.Private_keys = QPushButton('Private keys', self)
        self.Private_keys.setGeometry(1, 25, 100, 20)

        self.Private_keys.clicked.connect(self.hide_publi_address)


        self.Public_Keys_button = QPushButton('Public Keys', self)
        self.Public_Keys_button.setGeometry(103, 25, 100, 20)

        self.Public_Keys_button.clicked.connect(self.hide_priv_address)


        self.Addresses_button = QPushButton('Address', self)
        self.Addresses_button.setGeometry(206, 25, 100, 20)
        self.Addresses_button.clicked.connect(self.hide_publi_priv)

        self.label = QLabel('<b>Private Key :</b>', self)
        self.label.setGeometry(10, 50, 400, 20)

        self.generate_button = QPushButton('Generate a new key  ', self)
        self.generate_button.setGeometry(10, 85, 200, 30)

        self.import_button = QPushButton('Import a private key', self)
        self.import_button.setGeometry(220, 85, 200, 30)

        self.result_label = QLabel('', self)
        self.result_label.setGeometry(450, 100, 322, 20)

        self.label_addr = QLabel("<b>Address :</b>", self)
        self.label_addr.setGeometry(10, 50, 80, 20)

        self.legacy_address_label = QLabel('Legacy Address:', self)
        self.legacy_address_label.setGeometry(10, 80, 200, 20)

        self.legacy_address_field = QLineEdit(self)
        self.legacy_address_field.setGeometry(10, 100, 322, 20)

        self.p2pkh_address_label = QLabel('P2PKH Address:', self)
        self.p2pkh_address_label.setGeometry(10, 130, 200, 20)

        self.p2pkh_address_field = QLineEdit(self)
        self.p2pkh_address_field.setGeometry(10, 150, 322, 20)

        self.p2wpkh_address_label = QLabel('P2WPKH Address:', self)
        self.p2wpkh_address_label.setGeometry(10, 180, 200, 20)

        self.p2wpkh_address_field = QLineEdit(self)
        self.p2wpkh_address_field.setGeometry(10, 200, 322, 20)

        self.label_publi = QLabel("<b>Public keys:</b>", self)
        self.label_publi.setGeometry(10, 50, 80, 20)

        self.publickey_comp_label = QLabel("Public key compressed:", self)
        self.publickey_comp_label.setGeometry(10, 80, 450, 20)

        self.publickey_comp_field = QLineEdit(self)
        self.publickey_comp_field.setGeometry(10, 100, 500, 20)

        self.publickey_uncomp_label = QLabel("Public key uncompressed:", self)
        self.publickey_uncomp_label.setGeometry(10, 130, 450, 20)


        self.publickey_uncomp_field = QTextEdit(self)
        self.publickey_uncomp_field.setGeometry(10, 150, 500, 43)





        self.int_priv_label = QLabel('integer Private key:', self)
        self.int_priv_label.setGeometry(10, 130, 200, 20)


        self.int_priv_field = QLineEdit(self)
        self.int_priv_field.setGeometry(10, 150, 600, 20)

        self.uncomp_priv_label = QLabel('uncompressed private key:', self)
        self.uncomp_priv_label.setGeometry(10, 180, 200, 20)

        self.uncomp_priv_field = QLineEdit(self)
        self.uncomp_priv_field.setGeometry(10, 200, 430, 20)

        self.comp_priv_label = QLabel('compressed private key:', self)
        self.comp_priv_label.setGeometry(10, 230, 200, 20)

        self.comp_priv_field = QLineEdit(self)
        self.comp_priv_field.setGeometry(10, 250, 430, 20)



        self.generate_button.clicked.connect(self.randomkey)

        self.import_button.clicked.connect(self.show_import_private_key_window)

        self.legacy_address_label.hide()
        self.legacy_address_field.hide()
        self.p2pkh_address_label.hide()
        self.p2pkh_address_field.hide()
        self.p2wpkh_address_label.hide()
        self.p2wpkh_address_field.hide()
        self.label_addr.hide()

        self.label_publi.hide()
        self.publickey_comp_label.hide()
        self.publickey_comp_field.hide()
        self.publickey_uncomp_label.hide()
        self.publickey_uncomp_field.hide()

    def show_import_private_key_window(self):
        import_private_key_window = ImportPrivateKeyWindow(self)
        import_private_key_window.exec_()




    def randomkey(self):
        start_range = 2 ** 25
        end_range = 2 ** 256
        user_input = generate_random_number_in_range(start_range, end_range)
        self.generate_key_and_addresses(user_input)

    def take_user_input(self):
        user_input = self.input_field.text()
        self.generate_key_and_addresses(user_input)





    def hide_publi_address(self):

        self.label_addr.hide()
        self.legacy_address_label.hide()
        self.legacy_address_field .hide()
        self.p2pkh_address_label.hide()
        self.p2pkh_address_field.hide()
        self.p2wpkh_address_label.hide()
        self.p2wpkh_address_field.hide()

        self.label_publi.hide()
        self.publickey_comp_label.hide()
        self.publickey_comp_field.hide()
        self.publickey_uncomp_label.hide()
        self.publickey_uncomp_field.hide()

        self.import_button.show()
        self.int_priv_label.show()
        self.int_priv_field.show()
        self.uncomp_priv_label.show()
        self.uncomp_priv_field.show()
        self.comp_priv_label.show()
        self.comp_priv_field.show()
        self.label.show()

        self.generate_button.show()
        self.result_label.show()


    def hide_priv_address(self):
        self.legacy_address_label.hide()
        self.legacy_address_field.hide()
        self.p2pkh_address_label.hide()
        self.p2pkh_address_field.hide()
        self.p2wpkh_address_label.hide()
        self.p2wpkh_address_field.hide()
        self.label_addr.hide()

        self.import_button.hide()
        self.int_priv_label.hide()
        self.int_priv_field.hide()
        self.uncomp_priv_label.hide()
        self.uncomp_priv_field.hide()
        self.comp_priv_label.hide()
        self.comp_priv_field.hide()
        self.label.hide()

        self.generate_button.hide()
        self.result_label.hide()

        self.label_publi.show()
        self.publickey_comp_label.show()
        self.publickey_comp_field.show()
        self.publickey_uncomp_label.show()
        self.publickey_uncomp_field.show()





    def hide_publi_priv(self):

        self.label_publi.hide()
        self.publickey_comp_label.hide()
        self.publickey_comp_field.hide()
        self.publickey_uncomp_label.hide()
        self.publickey_uncomp_field.hide()


        self.import_button.hide()
        self.int_priv_label.hide()
        self.int_priv_field.hide()
        self.uncomp_priv_label.hide()
        self.uncomp_priv_field.hide()
        self.comp_priv_label.hide()
        self.comp_priv_field.hide()
        self.label.hide()

        self.generate_button.hide()
        self.result_label.hide()


        self.label_addr.show()
        self.legacy_address_label.show()
        self.legacy_address_field.show()
        self.p2pkh_address_label.show()
        self.p2pkh_address_field.show()
        self.p2wpkh_address_label.show()
        self.p2wpkh_address_field.show()



    def generate_key_and_addresses(self,user_input):


        try:
            user_input = int(user_input)
        except ValueError:
            self.result_label.setText('Invalid input. Please enter an integer.')
            return

        wif_private_key = generate_wif_key(user_input)
        private_key = wif_to_private_key(wif_private_key)
        public_key = private_key_to_public_key(private_key)
        public_key_nocompressed = private_key_to_public_key_nocompressed(private_key)

        p2pkh_address = adresse_legacy_nocompressed(user_input)
        p2wpkh_address = get_p2wpkh_address(public_key)
        legacy_address = adresse_legacy(user_input)

        self.int_priv_field.setText(str(user_input))
        self.uncomp_priv_field.setText(wif_private_key)
        self.comp_priv_field.setText(wif_compressed_private_key(user_input))

        self.legacy_address_field.setText(legacy_address.decode())
        self.p2pkh_address_field.setText(p2pkh_address)
        self.p2wpkh_address_field.setText(p2wpkh_address)

        self.publickey_comp_field.setText(public_key.hex())


        self.publickey_uncomp_field.setText(public_key_nocompressed.hex())



def generate_random_number_in_range(start, end):
    # Générer des octets aléatoires à l'aide de CSPRNG
    random_bytes = os.urandom(32)  # Utiliser 32 octets pour couvrir une plage jusqu'à 2^256

    # Convertir les octets en un nombre entier non signé
    random_unsigned_int = int.from_bytes(random_bytes, byteorder='big')

    # Mettre à l'échelle le nombre dans l'intervalle spécifié
    scaled_random_number = start + (random_unsigned_int % (end - start + 1))

    return scaled_random_number

def generate_wif_key(priv_key):

    priv_key_bytes = bytes.fromhex(hex(priv_key)[2:].zfill(64))
    wif_bytes = b'\x80' + priv_key_bytes
    checksum = hashlib.sha256(hashlib.sha256(wif_bytes).digest()).digest()[:4]
    wif_bytes += checksum
    wif_key = base58.b58encode(wif_bytes)

    return wif_key.decode()

def wif_compressed_private_key(priv_key):

    priv_key_bytes = bytes.fromhex(hex(priv_key)[2:].zfill(64))

    wif_bytes = b'\x80' + priv_key_bytes

    wif_bytes += b'\x01'

    checksum = hashlib.sha256(hashlib.sha256(wif_bytes).digest()).digest()[:4]
    wif_bytes += checksum

    # Convertir en base58
    wif_key = base58.b58encode(wif_bytes)

    return wif_key.decode()

def wif_to_private_key(wif_private_key):
    # Décoder la clé privée au format WIF
    decoded_key = base58.b58decode(wif_private_key)

    # Ignorer le préfixe de version (1 octet) et le suffixe de contrôle (4 octets)
    private_key = decoded_key[1:-4]

    return private_key

def private_key_to_public_key(private_key):
    # Générer une clé publique à partir de la clé privée
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key = verifying_key.to_string()

    # Appliquer le préfixe de compression (0x02 pour les clés publiques paires, 0x03 pour les impaires)
    compressed_prefix = b'\x02' if (public_key[31] % 2) == 0 else b'\x03'
    public_key = compressed_prefix + public_key[:32]

    return public_key

def private_key_to_public_key_nocompressed(private_key):
    # Générer une clé publique à partir de la clé privée
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key_nocompressed = verifying_key.to_string("uncompressed")
    hex_public_key_nocompressed = public_key_nocompressed

    return hex_public_key_nocompressed

def adresse_legacy(user_input):

    wif_private_key = generate_wif_key(user_input)
    private_key = wif_to_private_key(wif_private_key)

    public_key = private_key_to_public_key(private_key)

    hex_public_key = public_key.hex()
    # Hash SHA-256 de la clé publique
    hex_public_keysha256 = hashlib.sha256(bytes.fromhex(hex_public_key)).hexdigest()

    # Hash RIPEMD-160 du hash SHA-256
    hashed_data = RIPEMD160.new(bytes.fromhex(hex_public_keysha256)).hexdigest()


    # Ajouter le préfixe de version du réseau Bitcoin (0x00 pour Mainnet)
    version_prefixed_data = b'\x00' + bytes.fromhex(hashed_data)

    # Calculer la somme de contrôle (checksum)
    checksum = hashlib.sha256(hashlib.sha256(version_prefixed_data).digest()).digest()[:4]

    # Ajouter le checksum à la version préfixée
    final_data = version_prefixed_data + checksum

    # Encodage Base58Check pour obtenir l'adresse Bitcoin finale
    final_address = base58.b58encode(final_data)

    return final_address

def adresse_legacy_nocompressed(user_input):

    wif_private_key = generate_wif_key(user_input)
    private_key = wif_to_private_key(wif_private_key)
    public_key_nocompressed = private_key_to_public_key_nocompressed(private_key)
    public_key_nocompressed_hex = public_key_nocompressed.hex()

    # Hash SHA-256 de la clé publique
    hex_public_keysha256 = hashlib.sha256(bytes.fromhex(public_key_nocompressed_hex)).hexdigest()

    # Hash RIPEMD-160 du hash SHA-256
    hashed_data = RIPEMD160.new(bytes.fromhex(hex_public_keysha256)).hexdigest()


    # Ajouter le préfixe de version du réseau Bitcoin (0x00 pour Mainnet)
    version_prefixed_data = b'\x00' + bytes.fromhex(hashed_data)

    # Calculer la somme de contrôle (checksum)
    checksum = hashlib.sha256(hashlib.sha256(version_prefixed_data).digest()).digest()[:4]

    # Ajouter le checksum à la version préfixée
    final_data = version_prefixed_data + checksum

    # Encodage Base58Check pour obtenir l'adresse Bitcoin finale
    p2pkh_address = base58.b58encode(final_data)

    return p2pkh_address.decode()



def hash160(data):
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

def get_p2wpkh_address(public_key, hrp="bc"):

    # Étape 2: SHA-256 hashing sur la clé publique compressée
    sha256_hash = hashlib.sha256(public_key).digest()

    # Étape 3: RIPEMD-160 hashing sur le résultat de SHA-256
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    ripemd160_hash = ripemd160_hash.digest()

    # Étape 4: Conversion en tableau de 5-bit unsigned integers
    words = bech32.convertbits(ripemd160_hash, 8, 5)

    # Étape 5: Ajout du témoin de version (version actuelle est 0)
    witness_version_byte = bytes([0])
    data = witness_version_byte + bytes(words)
    # Étape 6: Calcul du checksum
    checksum = bech32.bech32_create_checksum(hrp, data)

    # Étape 7: Ajout du checksum au résultat de l'étape 5
    combined_data = data
    bech32_address = bech32.bech32_encode(hrp, combined_data)

    return bech32_address


def print_one():
    print("Button 1 clicked")

def print_two():
    print("Button 2 clicked")

def print_three():
    print("Button 3 clicked")



if __name__ == '__main__':
    app = QApplication(sys.argv)
    mw = MainWindow()
    mw.show()
    sys.exit(app.exec_())