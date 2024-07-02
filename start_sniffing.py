import pyfiglet
import os
from colored import fg, attr

def display_centered_text(text):
    terminal_width = os.get_terminal_size().columns
    centered_text = text.center(terminal_width)
    return centered_text

def display_banner():
    color1 = fg('red')
    color2 = fg('yellow')
    color3 = fg('blue')
    reset = attr('reset')

    # Utilisez la police 'Bloody'
    figlet = pyfiglet.Figlet(font='Bloody')
    banner_text = figlet.renderText('Packet Sniffing')

    for line in banner_text.split('\n'):
        centered_line = display_centered_text(line)
        print(f"{color1}{centered_line}{reset}")

    subtitle_color = color2
    subtitle_style = attr('bold')
    subtitle_text = "Developed by Soulaima Jaidane"
    centered_subtitle = display_centered_text(subtitle_text)
    print(f"{subtitle_color}{subtitle_style}{centered_subtitle}{reset}")
    print("")

    instruction_text = "Choose number 1 to begin sniffing."
    centered_instruction = display_centered_text(instruction_text)
    print(f"{color3}{centered_instruction}{reset}")

def main():
    display_banner()
    choice = input()

    if choice == "1":
        os.system('sudo python3 interface.py')
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
