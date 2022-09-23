import sys
sys.path.append('..')

import os
import nose

import util

test_location = os.path.dirname(os.path.realpath(__file__))


def run_deflat(binary, addr):
    os.system("python3 ./deflat.py -f %s --addr %#x" % (binary, addr))


def test_flat_control_flow():
    binary_path = os.path.join(test_location, 'samples', 'bin')

    flat_binary_x8664 = os.path.join(binary_path, 'check_passwd_x8664_flat')
    run_deflat(flat_binary_x8664, 0x400530)
    flat_binary_x8664_recovered = os.path.join(binary_path, 'check_passwd_x8664_flat_recovered')
    nose.tools.assert_equal(util.calc_md5(flat_binary_x8664_recovered), "e9a86d51e981a94d8756ecd94ffdc84a")

    flat_binary_arm = os.path.join(binary_path, 'check_passwd_arm_flat')
    run_deflat(flat_binary_arm, 0x83B0)
    flat_binary_arm_recovered = os.path.join(binary_path, 'check_passwd_arm_flat_recovered')
    nose.tools.assert_equal(util.calc_md5(flat_binary_arm_recovered), "5de3f39b502a87eab066a977b72da726")

    flat_binary_arm64 = os.path.join(binary_path, 'check_passwd_arm64_flat')
    run_deflat(flat_binary_arm64, 0x10000524C)
    flat_binary_arm64_recovered = os.path.join(binary_path, 'check_passwd_arm64_flat_recovered')
    nose.tools.assert_equal(util.calc_md5(flat_binary_arm64_recovered), "fb684b2f31a538c3bf103747f3b9c781")


if __name__ == "__main__":
    test_flat_control_flow()
