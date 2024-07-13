import random
import math
import tkinter as tk
from tkinter import ttk, messagebox

#Fermat primality test
def fermat_primality_test(number,k=5):
    if number <= 1:
        return False
    if number <= 3:
        return True
    for _ in range(k):
        a = random.randint(2,number-2)
        if pow(a,number-1,number) != 1:
            return False
    return True

#Function to generate a prime number within a given range
def generate_prime(min_value,max_value):
    prime = random.randint(min_value,max_value)
    while not fermat_primality_test(prime):
        prime = random.randint(min_value,max_value)
    return prime

#Function to find the modular inverse
def mod_inverse(e,phi):
    for d in range(3,phi):
        if (d*e)%phi == 1:
            return d 
    raise ValueError("MOD_INVERSE DOES NOT EXIST!")

#Function to generate keys
def generate_keys():
    global p, q, n, phi_n, e, d
    p = generate_prime(1000,50000)
    q = generate_prime(1000,50000)
    while p == q:
        q = generate_prime(1000,50000)
    n = p * q
    phi_n = (p - 1)*(q - 1)
    e = random.randint(3,phi_n-1)
    while math.gcd(e,phi_n) != 1:  # gcd = greatest common divisor
        e = random.randint(3,phi_n-1)
    d = mod_inverse(e,phi_n)
    update_keys_display(False)

def update_keys_display(show): #Function to update the key display on the GUI
    tree.delete(*tree.get_children())
    rows = [("Prime Number P", p),("Prime Number Q", q),("Public Key", e),("Private Key", d),("N", n),("Phi of N", phi_n)]
    for index,(key,value) in enumerate(rows):
        display_value = value if show else "****"
        tag='odd' if index%2 == 0 else 'even'
        tree.insert("","end",values=(key,display_value),tags=(tag,))
    tree.tag_configure('odd',background='#ECF0F1',foreground='#17202A')
    tree.tag_configure('even',background='#D5DBDB',foreground='#17202A')

#Function to encrypt the message
def encrypt_message():
    message = message_entry.get()
    if not message:
        messagebox.showwarning("Input Error","Please enter a message to encrypt.")
        return
    message_encoded = [ord(ch) for ch in message]
    ciphertext = [pow(ch,e,n) for ch in message_encoded]
    ciphertext_str = " ".join(map(str,ciphertext))
    cipher_text_label.config(state=tk.NORMAL)
    cipher_text_label.delete(1.0,tk.END)
    cipher_text_label.insert(tk.END,ciphertext_str)
    cipher_text_label.config(state=tk.DISABLED)

#Function to decrypt the message
def decrypt_message():
    ciphertext_str = cipher_text_label.get(1.0,tk.END).strip()
    if not ciphertext_str:
        messagebox.showwarning("Input Error","No ciphertext available to decrypt.")
        return
    ciphertext = list(map(int,ciphertext_str.split()))
    decoded_msg = [pow(ch,d,n) for ch in ciphertext]
    msg = "".join(chr(ch) for ch in decoded_msg)
    decrypted_text_label.config(state=tk.NORMAL)
    decrypted_text_label.delete(1.0,tk.END)
    decrypted_text_label.insert(tk.END,msg)
    decrypted_text_label.config(state=tk.DISABLED)

#Create the main window
root = tk.Tk()
root.title("RSA Encryption and Decryption")
root.geometry("700x600")
root.configure(bg="#17202A")

#Create and place widgets
title_label = tk.Label(root,text="RSA Encryption and Decryption",font=("Helvetica",16,"bold"),bg="#17202A",fg="#FDFEFE")
title_label.pack(pady=10)

msg_label = tk.Label(root,text="Enter your message to encrypt:",font=("Helvetica",12),bg="#17202A",fg="#FDFEFE")
msg_label.pack(pady=5)

message_entry = tk.Entry(root,width=50,font=("Helvetica",12))
message_entry.pack(pady=5)

button_frame = tk.Frame(root,bg="#17202A")
button_frame.pack(pady=10)

encrypt_button = tk.Button(button_frame,text="Encrypt",command=encrypt_message,font=("Helvetica", 12),bg="#3498DB",fg="#FDFEFE")
encrypt_button.pack(side=tk.LEFT,padx=10)
decrypt_button = tk.Button(button_frame,text="Decrypt",command=decrypt_message,font=("Helvetica", 12),bg="#E74C3C",fg="#FDFEFE")
decrypt_button.pack(side=tk.LEFT,padx=10)

#Frame for ciphertext with scrollbar
cipher_heading_label = tk.Label(root,text="CIPHERTEXT",font=("Helvetica",14,"bold"),bg="#17202A",fg="#FDFEFE",pady=10)
cipher_heading_label.pack()
cipher_frame = tk.Frame(root,bg="#17202A")
cipher_frame.pack(pady=5)

cipher_text_scrollbar = tk.Scrollbar(cipher_frame)
cipher_text_scrollbar.pack(side=tk.RIGHT,fill=tk.Y)
cipher_text_label = tk.Text(cipher_frame,height=4,width=80,font=("Helvetica",12), bg="#D5DBDB",fg="#17202A",wrap=tk.WORD,state=tk.DISABLED,yscrollcommand=cipher_text_scrollbar.set)
cipher_text_label.pack(side=tk.LEFT,fill=tk.BOTH, expand=True)
cipher_text_scrollbar.config(command=cipher_text_label.yview)

#Frame for decrypted text with scrollbar
decrypted_heading_label = tk.Label(root,text="DECRYPTED TEXT",font=("Helvetica",14 ,"bold"),bg="#17202A",fg="#FDFEFE",pady=10)
decrypted_heading_label.pack()
decrypted_frame = tk.Frame(root,bg="#17202A")
decrypted_frame.pack(pady=5)

decrypted_text_scrollbar = tk.Scrollbar(decrypted_frame)
decrypted_text_scrollbar.pack(side=tk.RIGHT,fill=tk.Y)
decrypted_text_label = tk.Text(decrypted_frame, height=4, width=80, font=("Helvetica", 12), bg="#D5DBDB", fg="#17202A", wrap=tk.WORD, state=tk.DISABLED, yscrollcommand=decrypted_text_scrollbar.set)
decrypted_text_label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
decrypted_text_scrollbar.config(command=decrypted_text_label.yview)

#Treeview for displaying keys
tree = ttk.Treeview(root,columns=("Key","Value"),show="headings",height=6)
tree.heading("Key",text="Key")
tree.heading("Value",text="Value")
tree.column("Key",anchor=tk.CENTER, width=200)
tree.column("Value",anchor=tk.CENTER,width=200)  #Center align and equal width for both columns
tree.pack(pady=20)
#Treeview styling
style = ttk.Style()
style.configure("Treeview",background="#D5DBDB",foreground="#17202A",fieldbackground="#D5DBDB",font=("Helvetica",12))
style.configure("Treeview.Heading",background="#BDC3C7",foreground="#17202A",font=("Helvetica",12,"bold"))
#Add VIEW and HIDE buttons
view_hide_frame = tk.Frame(root, bg="#17202A")
view_hide_frame.pack(pady=10)

view_button = tk.Button(view_hide_frame,text="VIEW",command=lambda: update_keys_display(True),font=("Helvetica",12),bg="#3498DB",fg="#FDFEFE")
view_button.pack(side=tk.LEFT,padx=10)
hide_button = tk.Button(view_hide_frame, text="HIDE", command=lambda: update_keys_display(False), font=("Helvetica",12),bg="#E74C3C",fg="#FDFEFE")
hide_button.pack(side=tk.LEFT,padx=10)

#Seed the random number generator
random.seed()
#Generate initial keys
generate_keys()
#Run the application
root.mainloop()