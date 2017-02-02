#!/usr/bin/env python2.7
# coding: UTF-8

import unittest
import instructions
from nao import eliminate


class TestEliminate(unittest.TestCase):

    def test_check_light_deadcode(self):
        expected = instructions.light_expected_list
        actual = eliminate.check_deadcode(instructions.light_arg_list)
        self.assertEqual(expected, actual)

    def test_check_heavy_deadcode(self):  # not pass test...
        expected = instructions.heavy_expected_list
        actual = eliminate.check_deadcode(instructions.heavy_arg_list)
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
