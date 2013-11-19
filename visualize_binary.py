#!/usr/bin/python
################################################################################
# The MIT License (MIT)
#
# Copyright (c) 2013 tandasat
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
################################################################################
"""Generates a PNG image file that represents the contents of a specified file.

Author: Satoshi Tanda

Description:
    Reads a specified file and converts each bytes to a pixel, and generates PNG
    image file that is named <input_file>.png in the same directory as an input
    file. The conversion rule follows the rule of a hex editor, Stirling. To use
    this script you need a PIL module:
        http://www.pythonware.com/products/pil/

Usage:
    $ python this.py <target_file>

Args:
    target_file: a target file path to create an image file.
"""

# Standard
import sys
import os
import math

# Third Party
import Image

# Original


def main(arg_values, arg_length):
    """Main routine"""

    if arg_length != 2:
        help(os.path.splitext(os.path.basename(sys.argv[0]))[0])
        return

    input_file_name = arg_values[1]
    input_file = open(input_file_name, "rb")
    input_data = bytearray(input_file.read())
    if len(input_data) == 0:
        print "Empty file."
        return

    IMAGE_WIDTH = 128
    image_size = (IMAGE_WIDTH,
        int(math.ceil(len(input_data) / (IMAGE_WIDTH * 1.0))))
    image = Image.new("RGB", image_size, "white")


    def convert_color(byte):
        """Decides a pixel color according to the rule of Stirling."""

        if   byte >= 0x80:
            return 0x000000
        elif byte >= 0x20:
            return 0x0000ff
        elif byte >= 0x01:
            return 0xffff00
        else:
            return 0xffffff


    def fill_image(input_data, image, image_size):
        """Puts color pixels on an image with color conversion"""

        y_range = range(image_size[1])
        x_range = range(IMAGE_WIDTH)
        d_range = len(input_data)
        pix = image.load()
        index = 0
        for y in y_range:
            for x in x_range:
                pix[x, y] = convert_color(input_data[index])
                index += 1
                if index >= d_range:
                    return
        return


    fill_image(input_data, image, image_size)
    image.convert("P").save(input_file_name + ".png", "PNG")
    return


if __name__ == "__main__":
    main(sys.argv, len(sys.argv))

