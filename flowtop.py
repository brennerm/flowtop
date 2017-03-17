import argparse

from flowtop.flow import FlowTop


def main():
    argparser = argparse.ArgumentParser()

    argparser.add_argument('interface')

    args = argparser.parse_args()

    FlowTop(interface=args.interface).run()


if __name__ == '__main__':
    main()
