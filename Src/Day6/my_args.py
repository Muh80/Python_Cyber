import argparse



def main():
    parser = argparse.ArgumentParser(description="Tiny Demo")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # greet subcommand
    p_greet = sub.add_parser("greet", help="say hello")
    p_greet.add_argument("name", help="the name to greet")

    # sum subcommand
    p_sum = sub.add_parser("sum", help="sum numbers")
    p_sum.add_argument("numbers", type=int, nargs='+', help="numbers to sum")

    # parse arguments
    args = parser.parse_args()

    if args.cmd == "greet":
        print(f"Hello, {args.name}!")
    elif args.cmd == "sum":
        print(f"The sum is: {sum(args.numbers)}")

if __name__ == "__main__":
    main()