def main():
    parser = argparse.ArgumentParser(description="Tiny Demo")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_greet = sub.add_parser("greet", help="say hello")
    p_greet.add_argument("__name__", required=True)


    p_add = sub.add_parser("sum", help="sum all numbers")
    p_add.add_argument("a", type=int, help="first number")
    p_add.add_argument("b", type=int, help="second number")

    
