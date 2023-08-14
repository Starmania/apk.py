"""
SYNOPSIS
    my_apk.py [SUBCOMMAND] [APK FILE|APK DIR|PKG NAME] [FLAGS]
    my_apk.py pull [PKG NAME] [FLAGS]
    my_apk.py decode [APK FILE] [FLAGS]
    my_apk.py build [APK DIR] [FLAGS]
    my_apk.py patch [APK FILE] [FLAGS]
    my_apk.py rename [APK FILE] [PKG NAME] [FLAGS]

SUBCOMMANDS
    pull	Pull an apk from device/emulator.
    decode	Decode an apk.
    build	Re-build an apk.
    patch	Patch an apk.
    rename	Rename the apk package.

FLAGS
    -a, --arch <arch>	Specify the target architecture, mandatory when patching.

    -g, --gadget-conf <json_file>
                Specify a frida-gadget configuration file, optional when patching.

    -n, --net		Add a permissing network security config when building, optional.
                It can be used with patch, pull and rename also.

    -s, --safe		Do not decode resources when decoding (i.e. apktool -r).
                Cannot be used when patching.

    -d, --no-dis		Do not disassemble dex, optional when decoding (i.e. apktool -s).
                Cannot be used when patching.

"""
import argparse
import json
import os
from platform import system as get_os
import re
import shutil
import subprocess
import sys
import zipfile
from lzma import open as lzma_open
from pathlib import Path
from typing import Literal, Optional

import requests
# from rich.progress import Progress


class ApkParser:
    """A class to parse apk files.

    Args:
        path (str, optional): _description_. Defaults to None.
        pkg_name (str, optional): _description_. Defaults to None.
        A path or a package name must be specified.
        If both are specified,

    Raises:
        FileNotFoundError: _description_
        ValueError: _description_

    The class is made to be reusable, so you can use it in your own scripts.
    But if the class child is deleted, it is easy to re-create it.
    """

    def __init__(self, path: str = None, pkg_name: str = None) -> None:
        self.apk_file = None
        self.apk_dir = None
        self.pkg_name = None

        self.tool = ToolUtils()

        if path:
            if Path(path).is_dir():
                self.apk_dir = Path(path)
            elif Path(path).is_file():
                self.apk_file = Path(path)
            else:
                raise FileNotFoundError(f"{path} not found.")

        if pkg_name:
            if re.match(r"^(?:[A-Za-z][A-Za-z\d_]*\.)+[A-Za-z][A-Za-z\d_]*$", pkg_name) is None:
                raise ValueError(f"{pkg_name} is not a valid package name.")
            self.pkg_name = pkg_name

    def _check_pos_args(self, positionnal_args):
        """Check if positionnal_args is a list or a tuple.

        Args:
            positionnal_args (Any): The positionnal arguments to check.

        Raises:
            ValueError: If positionnal_args is not a list or a tuple.

        Returns:
            list: The positionnal arguments as a list.
        """
        if positionnal_args is None:
            positionnal_args = []

        if not isinstance(positionnal_args, (list, tuple)):
            raise ValueError("Positionnal args must be a list or a tuple.")
        positionnal_args = list(positionnal_args)
        return positionnal_args

    def pull(self, net=False):
        """Pull an apk from device/emulator.

        Args:
            net (bool, optional): Add a network security config. Defaults to False.

        Raises:
            ValueError: If the package name is not set. This is mandatory.
        """
        if self.pkg_name is None:
            raise ValueError("Package name not set.")

        pull_args = []
        if net:
            pull_args += ["-n"]

        if is_not_installed("adb"):
            print("[>] No adb found!")
            print("[>] Pls install adb!")
            print("[>] Bye!")
            sys.exit(1)

        # Searching for apk(s) path(s) on the device
        try:  # In case of pkg not found
            output: str = subprocess.check_output(
                ["adb", "shell", "pm", "path", self.pkg_name],
                text=True, stderr=subprocess.STDOUT).strip()
            pkg_path = [path.split(':')[1].strip(
            ) if path else None for path in output.splitlines()]
        except subprocess.CalledProcessError:
            pkg_path = []

        if len(pkg_path) == 0 or pkg_path[0] is None:
            print(f"[>] Sorry, cant find package {self.pkg_name}")
            print("[>] Bye!")
            sys.exit(1)
        num_apk = len(pkg_path)
        pkg_path_str = ", ".join(pkg_path)

        if num_apk > 1:
            split_dir = Path(self.pkg_name + "_split_apks")
            if split_dir.is_dir():
                shutil.rmtree(split_dir)
            split_dir.mkdir(parents=True, exist_ok=True)
            print(f"[>] Pulling {self.pkg_name}: Split apks detected!")
            print(f"[>] Pulling {num_apk} apks in {split_dir}")
            print_(f"[>] Pulling {self.pkg_name} from {pkg_path_str}<<<")

            for package in pkg_path:
                pull_cmd = f"adb pull {package} {split_dir}"
                run(pull_cmd)
            # We have to combine split APKs into a single APK, for patching.
            # Decode all the APKs.
            print("[>] Combining split APKs into a single APK...")
            if Path(f"{self.pkg_name}_tmp.apk").is_file():
                os.remove(f"{self.pkg_name}_tmp.apk")
            self.tool.apkeditor("m", "-i", str(split_dir),
                                "-o", f"{self.pkg_name}_tmp.apk")

            print("[>] Done!")
            out = split_dir / "out"
            self.tool.apkeditor(
                "d", "-i", f"{self.pkg_name}_tmp.apk", "-o", f"{out}", "-dex", "-t", "json")
            manifest = out / "AndroidManifest.xml.json"
            manifest_content = json.loads(manifest.read_text())
            # Set android:extractNativeLibs="true" in the Manifest
            # if you experience any adb: failed to install file.gadget.apk:
            #   Failure [INSTALL_FAILED_INVALID_APK: Failed to extract native libraries, res=-2]
            print("[>] Enabling native libraries extraction if it was set to false...")
            # If the tag exist and is set to false, set it to true, otherwise do nothing
            for element in manifest_content["element"]["childes"]:
                if element["name"] == "application":
                    for attribute in element.get("attributes", []):
                        if "extractNativeLibs" in attribute["name"]:
                            if attribute["value"] == "false":
                                print("[>] Setting extractNativeLibs to true...")
                                attribute["value"] = "true"
                            break
                    break
            manifest.write_text(json.dumps(manifest_content))
            print("[>] Done!")
            # Rebuild the base APK
            print("[>] Rebuilding the base APK...")
            self.tool.apkeditor(
                "b", "-i", f"{out}", "-o", f"{self.pkg_name}.apk")
            shutil.rmtree(split_dir)
            os.remove(f"{self.pkg_name}_tmp.apk")
            print("[>] Bye!")
        else:
            print(f"[>] Pulling {self.pkg_name} from {pkg_path[0]}")
            pull_cmd = f"adb pull {pkg_path[0]} ."
            run(pull_cmd)
            # Rename to pkg_name.apk
            os.rename(Path(pkg_path[0]).name, f"{self.pkg_name}.apk")
            print("[>] Done!")
            print("[>] Bye!")

        self.apk_file = Path(f"{self.pkg_name}.apk")

    def decode(self, safe=False, no_disassemble=False,
               # no_decode=False, # Only for debugging
               positionnal_args: list | tuple = None
               ) -> None:
        """Decode an apk.

        Args:
            safe (bool, optional): Does not decode ressources. Defaults to False.
            no_disassemble (bool, optional): Does not decode into smali. Defaults to False.
            positionnal_args (list | tuple, optional):\
                Any arguments you would like to pass to apktool.

        Raises:
            ValueError: If the apk file is not set. This is mandatory.
        """
        if self.apk_file is None:
            raise ValueError("Apk file not set.")

        positionnal_args = self._check_pos_args(positionnal_args)

        force_flag = "-f" in positionnal_args

        if "-o" in positionnal_args:
            index = positionnal_args.index("-o")
            out_path = Path(positionnal_args[index + 1])
            positionnal_args.pop(index)
            positionnal_args.pop(index)
        else:
            out_path = self.apk_file.parent / self.apk_file.stem
            if not force_flag and out_path.is_dir():
                i = 0
                while out_path.is_dir():
                    out_path = self.apk_file.parent / \
                        (f"{self.apk_file.stem}_{i}")
                    i += 1

        decode_args = ["d", "-o", str(out_path)]
        if safe:
            decode_args += ["-r"]

        if no_disassemble:
            decode_args += ["-s"]

        if len(positionnal_args) > 0:
            decode_args += list(positionnal_args)

        decode_args += [str(self.apk_file)]

        _ = ", ".join(decode_args)
        print(
            f"[>] \033[1mDecoding {self.apk_file.name}\033[0m with apktool({_})")
        self.tool.apktool(*decode_args)
        self.apk_dir = out_path

        print("[>] Done!")

    def build(self, net=False, positionnal_args: list = None):
        """Build an apk directory.

        Args:
            net (bool, optional): Add a network security config. Defaults to False.
            positionnal_args (list, optional): Any arguments you would like to pass to apktool.

        Raises:
            ValueError: If the apk directory is not set. This is mandatory.:
            ValueError: Positionnal args are invalid.
        """
        if self.apk_dir is None:
            raise ValueError("Apk directory not set.")

        positionnal_args = self._check_pos_args(positionnal_args)

        if "-o" in positionnal_args:
            index = positionnal_args.index("-o")
            apk_name = positionnal_args[index + 1]
            positionnal_args.pop(index)
            positionnal_args.pop(index)
        else:
            apk_name = Path(f"{self.apk_dir.name}.apk")
            if apk_name.is_file():
                i = 0
                while apk_name.is_file():
                    apk_name = Path(f"{self.apk_dir.name}_{i}.apk")
                    i += 1

        build_args = ["b", "-d", str(self.apk_dir),
                      "-o", str(apk_name), "--use-aapt2"]
        if net:
            build_args += ["-n"]
            (self.apk_dir / "res" / "xml").mkdir(parents=True, exist_ok=True)

        if len(positionnal_args) > 0:
            build_args += list(positionnal_args)

        _ = ", ".join(build_args)

        print(f"[>] \033[1mBuilding\033[0m with apktool({_})")
        self.tool.apktool(*build_args)
        print("[>] Built!")
        print("[>] Aligning with zipalign -p 4 ....")
        self.tool.zipalign("-p", "4", str(apk_name), f"{apk_name}-aligned.apk")
        print("[>] Done!")

        keystore = APK_PY_HOME / "my-new.keystore"
        if not keystore.is_file():
            print("[!] Keystore does not exist!")
            print("[>] Generating keystore...")
            run(f'keytool -genkey -v -keystore {keystore} -alias alias_name \
                -keyalg RSA -keysize 2048 -validity 10000 -storepass password \
                -keypass password -noprompt \
                -dname "CN=noway, OU=ID, O=Org, L=Blabla, S=Blabla, C=US"')
        else:
            print("[>] A Keystore exist!")
        print(f"[>] Signing {apk_name} with apksigner...")
        self.tool.apksigner("sign", "--ks", str(keystore), "--ks-pass",
                            "pass:password", f'"{apk_name}-aligned.apk"')
        os.remove(str(apk_name))
        os.rename(f"{apk_name}-aligned.apk", str(apk_name))
        print("[>] Done!")
        print(f"[>] {apk_name} ready!")

    def patch(self, arch: Literal["arm", "arm64", "x86", "x86_64"],
              gadget_conf=None, net=False, positionnal_args: list = None):
        """Patch an apk file.

        Add the Frida gadget to the apk.

        Args:
            arch (str): The architecture of the gadget to inject.
            gadget_conf (str, optional): The Path to a frida-gadget configuration file.\
                Defaults to None.
            net (bool, optional): If a network security config should be added.\
                Defaults to False.
            positionnal_args (list, optional): Any arguments you would like to pass to apktool.\
                Defaults to None.

        Raises:
            ValueError: If the apk file is not set. This is mandatory.
            ValueError: If the architecture is not supported.
            ValueError: If the positionnal_args are invalid.
            FileNotFoundError: If the gadget_conf file is not found.
        """
        if self.apk_file is None:
            raise ValueError("Apk file not set.")

        if arch not in SUPPORTED_ARCH:
            raise ValueError(f"{arch} is not a supported architecture.")

        gadget_conf = Path(gadget_conf) if gadget_conf else None
        if gadget_conf and not gadget_conf.is_file():
            raise FileNotFoundError(f"{gadget_conf} not found.")

        positionnal_args = self._check_pos_args(positionnal_args)

        if "-o" in positionnal_args:
            index = positionnal_args.index("-o")
            out_file = Path(positionnal_args[index + 1])
            positionnal_args.pop(index)
            positionnal_args.pop(index)
        else:
            out_file = self.apk_file.parent / \
                f"{self.apk_file.stem}.gadget.apk"
            if out_file.is_file():
                i = 0
                while out_file.is_file():
                    out_file = self.apk_file.parent / \
                        f"{self.apk_file.stem}_{i}.gadget.apk"
                    i += 1
        patch_args = ["-o", str(out_file)]

        if len(positionnal_args) > 0:
            patch_args += list(positionnal_args)

        self.tool.locate_gadget(arch)
        arch_dir = ARCHS[arch]

        self.decode()

        print("[>] \033[1mInjecting Frida gadget...\033[0m")
        print(f"[>] Placing the Frida shared object for {arch}....")

        (self.apk_dir / "lib" / arch_dir).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.tool.frida_so[arch], (self.apk_dir / "lib" /
                        arch_dir / "libfrida-gadget.so"))
        if gadget_conf:
            print("[>] Placing the specified gadget configuration json file....")
            shutil.copyfile(gadget_conf, (self.apk_dir / "lib" /
                            arch_dir / "libfrida-gadget.config.so"))

        # Inject a System.loadLibrary("frida-gadget") call into the smali,
        # before any other bytecode executes or any native code is loaded.
        # A suitable place is typically the static initializer of the
        # entry point class of the app (e.g. the main application Activity).
        # We have to determine the class name for the activity that
        # is launched on application startup.
        # In Objection this is done by first trying to parse the output of aapt dump badging,
        # then falling back to manually parsing the AndroidManifest for activity-alias tags.
        print("[>] Searching for a launchable-activity...")
        output = self.tool.apkeditor(
            "info", "-activities", "-i", str(self.apk_file), parse_output=True)
        main_activity_class = re.search(
            r"activity-main=\"([^\"]+)\"", output).group(1)
        print(f"[>] launchable-activity found --> {main_activity_class}")
        # Try to determine the local path for a target class' smali converting the main activity to a path
        main_activity_2path = main_activity_class.replace(".", "/")
        class_path = Path(self.apk_dir) / "smali" / \
            f"{main_activity_2path}.smali"
        print(f"[>] Local path should be {class_path}")
        # INFO: if the class does not exist it might be a multidex setup.
        # Search the class in smali_classesN directories.
        class_path_index = 1  # starts from 2
        # get max number of smali_classes
        class_path_index_max = len(list(self.apk_dir.glob("*_classes[0-9]*")))
        while not class_path.is_file():
            print(f"[!] {class_path} does not exist! Probably a multidex APK...")
            if class_path_index > class_path_index_max:
                # keep searching until smali_classesN then exit
                print(f"[>] {class_path} NOT FOUND!")
                print("[!] Can't find the launchable-activity! Sorry.")
                print("[>] Bye!")
                sys.exit(1)
            class_path_index += 1
            # ./base/smali/
            # ./base/smali_classes2/
            class_path = self.apk_dir / \
                f"smali_classes{class_path_index}" / \
                f"{main_activity_2path}.smali"
            print(f"[?] Looking in {class_path}...")

        # pylint: disable=pointless-string-statement
        """
        Now, patch the smali, look for the line with the apktool's comment "# direct methods"
        Patch the smali with the appropriate loadLibrary call based on wether a constructor already exists or not.
        If an existing constructor is present, the partial_load_library will be used.
        If no constructor is present, the full_load_library will be used.

        Objection checks if there is an existing <clinit> to determine which is the constructor,
        then they inject a loadLibrary just before the method end.

        We search for *init> and inject a loadLibrary just after the .locals declaration.

        <init> is the (or one of the) constructor(s) for the instance, and non-static field initialization.
        <clinit> are the static initialization blocks for the class, and static field initialization.
        """

        print(f"[>] {class_path} found!")
        print("[>] Patching smali...")
        lines = class_path.read_text().splitlines()
        index = 0
        skip = 1
        for line in range(len(lines)):  # pylint: disable=consider-using-enumerate
            # partial_load_library
            if lines[line] == "# direct methods":
                if "init>" in lines[line + 1]:
                    print(
                        f"[>>] A constructor is already present --> {lines[index + 1]}")
                    print("[>>] Injecting partial load library!")
                    # Skip  any .locals and write after
                    # Do we have to skip .annotaions? is ok to write before them?
                    if ".locals" in lines[line + 2]:
                        print("[>>] .locals declaration found!")
                        print("[>>] Skipping .locals line...")
                        skip = 2
                        print("[>>] Update locals count...")
                        locals_count = int(lines[line + 2].split()[1]) + 1
                        lines[line + 2] = f".locals {locals_count}"
                    else:
                        print("[!!!!!!] No .locals found! :(")
                        print("[!!!!!!] TODO add .locals line")

                    # We inject a loadLibrary just after the locals delcaration.
                    # Objection add the loadLibrary call just before the method end.
                    arr = lines[: line + 1 + skip]  # start of the list
                    arr.append('const-string v0, "frida-gadget"')
                    arr.append(
                        'invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V')
                    arr.extend(lines[line + 1 + skip:])  # tail of the list
                    lines = arr  # assign back to the original list
                else:
                    print("[!!!!!!] No constructor found!")
                    print("[!!!!!!] TODO: gonna use the full load library")
                    # arr.append('.method static constructor <clinit>()V')
                    # arr.append('   .locals 1')
                    # arr.append('')
                    # arr.append('   .prologue')
                    # arr.append('   const-string v0, "frida-gadget"')
                    # arr.append('')
                    # arr.append('   invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V')
                    # arr.append('')
                    # arr.append('   return-void')
                    # arr.append('.end method')
            index += 1
        print("[>] Writing the pathced smali back...")
        class_path.write_text("\n".join(lines))

        # Add the Internet permission to the manifest if it’s not there already,
        # to permit Frida gadget to open a socket.
        print("[?] Checking if Internet permission is present in the manifest...")
        INTERNET_PERMISSION = False
        MANIFEST_PATH: Path = self.apk_dir / "AndroidManifest.xml"
        manifest = MANIFEST_PATH.read_text().splitlines()
        for line in manifest:
            if '<uses-permission android:name="android.permission.INTERNET"/>' in line:
                INTERNET_PERMISSION = True
                print("[>] Internet permission is there!")
                break
        if not INTERNET_PERMISSION:
            print("[!] Internet permission not present in the Manifest!")
            print(f"[>] Patching {MANIFEST_PATH}")
            arr = [manifest[0]]  # start of the list
            arr.append(
                '<uses-permission android:name="android.permission.INTERNET"/>')
            arr.extend(manifest[1:])  # tail of the list
            MANIFEST_PATH.write_text("\n".join(arr))

        self.build(net=net, positionnal_args=patch_args)
        print("[>] Bye!")

    def rename(self, pkg_name: str, net=False, positionnal_args: list = None):
        """Rename the apk package.

        Args:
            pkg_name (str): The new package name.
            net (bool, optional): Add a network security config. Defaults to False.
            positionnal_args (list, optional): Any arguments you would like to pass to apktool.\
                Defaults to None.
        """
        print(f"[>] \033[1mRenaming {self.apk_file}\033[0m to {pkg_name}")

        positionnal_args = self._check_pos_args(positionnal_args)

        if "-o" in positionnal_args:
            index = positionnal_args.index("-o")
            out_file = Path(positionnal_args[index + 1])
            positionnal_args.pop(index)
            positionnal_args.pop(index)
        else:
            out_file = self.apk_file.parent / \
                f"{pkg_name}.renamed.apk"
            if out_file.is_file():
                i = 0
                while out_file.is_file():
                    out_file = self.apk_file.parent / \
                        f"{pkg_name}_{i}.renamed.apk"
                    i += 1

        rename_args = ["-o", str(out_file)] + positionnal_args
        self.decode()
        apktool_tml_path: Path = self.apk_dir / "apktool.yml"
        print(
            f"[>] Updating renameManifestPackage in apktool.yml with {pkg_name}")
        # Note: https://github.com/iBotPeaches/Apktool/issues/1753
        # renameManifestPackage is not designed for manual package name changes,
        # but can be useful in some situations.
        file_content = apktool_tml_path.read_text()
        updated_content = re.sub(r'renameManifestPackage:.+',
                                 f'renameManifestPackage: {pkg_name}', file_content)
        apktool_tml_path.write_text(updated_content)
        # Silently build
        self.build(net=net, positionnal_args=rename_args)


class ToolUtils:
    """A class to locate and use tools.

    Args:
        use_path (bool, optional): If you want to use the path to search tools.\
            Defaults to False.
    """

    def __init__(self, use_path=False) -> None:
        self.frida_so_xz: dict[str, Path] = {
            arch_name: None for arch_name in SUPPORTED_ARCH}
        self.frida_so: dict[str, Path] = {
            arch_name: None for arch_name in SUPPORTED_ARCH}

        if not APK_PY_HOME.is_dir():
            APK_PY_HOME.mkdir(parents=True, exist_ok=True)

        self.locate_all(use_path=use_path)

    def locate_all(self, use_path=False) -> None:
        """Locate all tools.

        Args:
            use_path (bool, optional): Should we allow tools already in PATH to be used.\
            Defaults to False.
        """
        self.apktool_path = locate(
            f"apktool_{APKTOOL_VER}.jar", use_path=use_path)
        self.apkeditor_path = locate(
            f"APKEditor-{APKEDITOR_VER}.jar", use_path=use_path)
        self.apksigner_path = locate("apksigner", use_path=use_path)
        self.zipalign_path = locate("zipalign", use_path=use_path)
        self.aapt_path = locate("aapt", use_path=use_path)
        self.aapt2_path = locate("aapt2", use_path=use_path)

    def locate_gadget(self, arch: Literal["arm", "arm64", "x86", "x86_64"]) -> None:
        """Locate the frida gadget for the specified architecture.

        Args:
            arch (&quot;arm&quot;, &quot;arm64&quot;, &quot;x86&quot;, &quot;x86_64&quot;):\
                The architecture of the gadget to locate.

        Raises:
            ValueError: If the architecture is not supported.
        """

        if arch not in SUPPORTED_ARCH:
            raise ValueError(f"{arch} is not a supported architecture.")

        gadget_file_name = f"frida-gadget-{GADGET_VER}-android-{arch}.so.xz"

        self.frida_so_xz[arch] = APK_PY_HOME / gadget_file_name
        self.frida_so[arch] = self.frida_so_xz[arch].parent / \
            self.frida_so_xz[arch].stem

        if not self.frida_so[arch].is_file():
            print(f"[!] Frida gadget not present in {APK_PY_HOME}")
            if not self.frida_so_xz[arch].is_file():
                self.download_gadget(arch)
            self.extract_gadget(arch)
        else:
            print(f"[>] Frida gadget already present in {APK_PY_HOME}")

    def download_gadget(self, arch: Literal["arm", "arm64", "x86", "x86_64"]) -> None:
        """Download the frida gadget for the specified architecture.

        Does not extract it.

        Args:
            arch (&quot;arm&quot;, &quot;arm64&quot;, &quot;x86&quot;, &quot;x86_64&quot;):\
                The architecture to download.
        """
        if arch not in SUPPORTED_ARCH:
            raise ValueError(f"{arch} is not a supported architecture.")

        if self.frida_so_xz[arch] is None:
            raise ValueError(
                f"No frida gadget archive path set for arch {arch}.")

        print(
            f"[>] Downloading latest frida gadget for {arch} from github.com...")
        wget(path=self.frida_so_xz[arch],
             url=f"https://github.com/frida/frida/releases/download/{GADGET_VER}/{self.frida_so_xz[arch].name}")
        # TODO: Allow a different name to be saved to.

    def extract_gadget(self, arch: Literal["arm", "arm64", "x86", "x86_64"]) -> None:
        """Extract the frida gadget for the specified architecture.

        Args:
            arch (&quot;arm&quot;, &quot;arm64&quot;, &quot;x86&quot;, &quot;x86_64&quot;):\
                The architecture to extract.
        """
        if arch not in SUPPORTED_ARCH:
            raise ValueError(f"{arch} is not a supported architecture.")

        if self.frida_so_xz[arch] is None:
            raise ValueError(
                f"No frida gadget archive path set for arch {arch}.")

        if self.frida_so[arch] is None:
            raise ValueError(f"No frida gadget path set for arch {arch}.")

        with lzma_open(self.frida_so_xz[arch], mode="rb") as xz_file:
            with open(self.frida_so[arch], mode="wb") as output:
                shutil.copyfileobj(xz_file, output)

    def check_apk_tools(self) -> None:
        """Check for tools to be present. If not, install them.

        Check for:
            - apktool
            - apkeditor

            - apksigner
            - zipalign
            - aapt
            - aapt2
        """
        print("[>] Using apktool version: " + APKTOOL_VER)
        print("[>] Using apkeditor version: " + APKEDITOR_VER)
        print("[>] Using build-tools version: " + BUILDTOOLS_VER)

        if not self.apktool_path:
            self.install_apktool()

        if not self.apkeditor_path:
            self.install_apkeditor()

        every_buildtool_exists = all([self.apksigner_path, self.zipalign_path,
                                     self.aapt_path, self.aapt2_path])  # pylint: disable=line-too-long
        if not every_buildtool_exists:
            self.install_buildtools()

        version = subprocess.check_output(
            [self.apksigner_path, "--version"], text=True).strip()
        print(f"[*] apksigner v{version} exist in {self.apksigner_path}")

    def install_apktool(self) -> None:
        """Install apktool (Thanks to iBotPeaches for this)
        """
        # pylint: disable=attribute-defined-outside-init
        APKTOOL_DOWNLOAD_URL_GH = f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VER}/apktool_{APKTOOL_VER}.jar"
        APKTOOL_DOWNLOAD_URL = APKTOOL_DOWNLOAD_URL_GH
        print(f"[!] No apktool v{APKTOOL_VER} found!")
        print(f"[>] Downloading apktool from {APKTOOL_DOWNLOAD_URL}")
        wget(path=APK_PY_HOME / Path(APKTOOL_DOWNLOAD_URL).name,
             url=APKTOOL_DOWNLOAD_URL)
        self.apktool_path = APK_PY_HOME / Path(APKTOOL_DOWNLOAD_URL).name

    def install_apkeditor(self) -> None:
        """Install apkeditor (Thanks to REAndroid for a really fast tool)
        """
        # pylint: disable=attribute-defined-outside-init
        APKEditor_DOWNLOAD_URL_GH = f"https://github.com/REAndroid/APKEditor/releases/download/V{APKEDITOR_VER}/APKEditor-{APKEDITOR_VER}.jar"
        APKEditor_DOWNLOAD_URL = APKEditor_DOWNLOAD_URL_GH
        print(f"[!] No apkeditor v{APKEDITOR_VER} found!")
        print(f"[>] Downloading apkeditor from {APKEditor_DOWNLOAD_URL}")
        wget(path=APK_PY_HOME / Path(APKEditor_DOWNLOAD_URL).name,
             url=APKEditor_DOWNLOAD_URL)
        self.apkeditor_path = APK_PY_HOME / Path(APKEditor_DOWNLOAD_URL).name

    def install_buildtools(self) -> None:
        """Install Android build-tools

        Make available:
            - apksigner
            - zipalign
            - aapt
            - aapt2
        """
        # pylint: disable=invalid-name
        system = {"Windows": "win", "Linux": "linux",
                  "Darwin": "mac"}.get(get_os(), None)
        if not system:
            print(f"[>] Unsupported operating system: {get_os()}")
            print("[>] Pls use another OS!")
            print("[>] Bye!")
            sys.exit(1)

        CMDLINE_TOOLS_DL_URL = f"https://dl.google.com/android/repository/commandlinetools-{system}-9123335_latest.zip"
        CMDLINE_TOOLS_ZIP = APK_PY_HOME / Path(CMDLINE_TOOLS_DL_URL).name
        CMDLINE_TOOLS_DIR = APK_PY_HOME / "cmdline-tools"

        if not CMDLINE_TOOLS_DIR.is_dir():
            print(
                f"[>] Downloading Android commandline tools from {CMDLINE_TOOLS_DL_URL}")
            wget(path=CMDLINE_TOOLS_ZIP, url=CMDLINE_TOOLS_DL_URL)
            with zipfile.ZipFile(CMDLINE_TOOLS_ZIP, mode="r") as zip_ref:
                zip_ref.extractall(APK_PY_HOME)
            CMDLINE_TOOLS_ZIP.unlink()

        sdk_manager_bin_path = CMDLINE_TOOLS_DIR / "bin" / "sdkmanager"
        SDK_ROOT.mkdir(parents=True, exist_ok=True)
        install_buildtools_cmd = ""
        if get_os() == "Linux":
            install_buildtools_cmd = "yes |"
        install_buildtools_cmd += f"{sdk_manager_bin_path} \"build-tools;{BUILDTOOLS_VER}\" \
            \"--sdk_root={SDK_ROOT}\""
        print(f"[>] Installing build-tools {BUILDTOOLS_VER}...")
        update_perms()
        run(install_buildtools_cmd)
        update_perms()
        self.locate_all()
        print("[>] Done!")

    # pylint: disable=missing-function-docstring
    def apktool(self, *args):
        if self.apktool_path is None:
            raise FileNotFoundError("apktool not found!")

        java_path = Path(shutil.which("java"))

        if os.environ.get("JAVA_HOME", None) is not None:
            java_path = Path(os.environ["JAVA_HOME"]) / "bin" / "java"

        run(f"\"{java_path}\" -jar \"{self.apktool_path}\" {' '.join(args)}")

    def apkeditor(self, *args, parse_output=False) -> Optional[str]:
        if self.apkeditor_path is None:
            raise FileNotFoundError("apkeditor not found!")

        java_path = Path(shutil.which("java"))

        if os.environ.get("JAVA_HOME", None) is not None:
            java_path = Path(os.environ["JAVA_HOME"]) / "bin" / "java"

        if parse_output:
            return subprocess.check_output(
                f"\"{java_path}\" -jar \"{self.apkeditor_path}\" {' '.join(args)}",
                text=True, shell=True).strip()

        run(f"\"{java_path}\" -jar \"{self.apkeditor_path}\" {' '.join(args)}")
        return None

    def apksigner(self, *args):
        if self.apksigner_path is None:
            raise FileNotFoundError("apksigner not found!")
        run(f"{self.apksigner_path} {' '.join(args)}")

    def zipalign(self, *args):
        if self.zipalign_path is None:
            raise FileNotFoundError("zipalign not found!")
        run(f"{self.zipalign_path} {' '.join(args)}")

    def aapt(self, *args):
        if self.aapt_path is None:
            raise FileNotFoundError("aapt not found!")
        run(f"{self.aapt_path} {' '.join(args)}")

    def aapt2(self, *args):
        if self.aapt2_path is None:
            raise FileNotFoundError("aapt2 not found!")
        run(f"{self.aapt2_path} {' '.join(args)}")


def parse_args() -> argparse.Namespace:
    """Parse the command line arguments.

    Returns:
        Namespace: The parsed arguments.
    """
    # pylint: disable=unused-variable, too-many-locals
    # Ok, there is unused variables, but it's for readability.
    # And I use a lot of locals, but it's really nedded.
    main_parser = argparse.ArgumentParser()

    # Main parameters
    apk_file_parser = argparse.ArgumentParser(add_help=False)
    apk_file_parser.add_argument(
        "APK_FILE", type=str, metavar="FILE",
        help="The path of the apk to use for")

    apk_dir_parser = argparse.ArgumentParser(add_help=False)
    apk_dir_parser.add_argument(
        "APK_DIR", type=str, metavar="DIRECTORY",
        help="The directory of the apk to use for")

    pkg_name_parser = argparse.ArgumentParser(add_help=False)
    pkg_name_parser.add_argument(
        "PKG_NAME", metavar="PACKAGE_NAME",
        help="The package name (com.example.app) to use for")

    # Flags
    arch_flag = argparse.ArgumentParser(add_help=False)
    arch_flag.add_argument(
        "--arch", choices=SUPPORTED_ARCH, required=True,
        help="Specify the target architecture.",
        dest="arch")

    gadget_conf_flag = argparse.ArgumentParser(add_help=False)
    gadget_conf_flag.add_argument(
        "--gadget-conf", "-g", type=str,
        metavar="FILE", help="Specify a frida-gadget configuration file, optional when patching.",
        dest="gadget_conf")

    net_flag = argparse.ArgumentParser(add_help=False)
    net_flag.add_argument(
        "--net", "-n", action="store_true",
        help="Add a permissing network security config when building, optional.",
        dest="net")

    safe_flag = argparse.ArgumentParser(add_help=False)
    safe_flag.add_argument(
        "--safe", "-s", action="store_true",
        help="Do not decode resources when decoding(i.e. apktool -r).",
        dest="safe")

    no_disassemble_flag = argparse.ArgumentParser(add_help=False)
    no_disassemble_flag.add_argument(
        "--disass", "-d", action="store_true",
        help="Do not disassemble dex, optional when decoding (i.e. apktool -s).",
        dest="no_disassemble")

    positional_flag = argparse.ArgumentParser(add_help=False)
    positional_flag.add_argument(
        "--positional", type=str,
        nargs='*', help="positional args",
        dest="positionnal_args")

    # Subcommands
    subcommand_parser = main_parser.add_subparsers(
        required=True, dest="action")

    pull_parser = subcommand_parser.add_parser(
        "pull", parents=[pkg_name_parser, net_flag],
        help="Pull an apk from device/emulator.")

    decode_parser = subcommand_parser.add_parser(
        "decode", parents=[apk_file_parser, safe_flag, no_disassemble_flag, positional_flag],
        help="Decode an apk.")

    build_parser = subcommand_parser.add_parser(
        "build", parents=[apk_dir_parser, net_flag, positional_flag],
        help="Re-build an apk.")

    patch_parser = subcommand_parser.add_parser(
        "patch", parents=[apk_file_parser, arch_flag, gadget_conf_flag, net_flag, positional_flag],
        help="Patch an apk.")

    rename_parser = subcommand_parser.add_parser(
        "rename", parents=[apk_file_parser, pkg_name_parser, net_flag],
        help="Rename the apk package.")

    return main_parser.parse_args()


def get_parser(args: dict[str]):
    if "action" not in args:
        raise ValueError("No action specified")

    action = args["action"]
    del args["action"]

    if action in ["decode", "patch", "rename"]:
        apk_parser = ApkParser(path=args["file"])
        del args["file"]
    elif action in ["build"]:
        apk_parser = ApkParser(path=args["dir"])
        del args["dir"]
    elif action in ["pull"]:
        apk_parser = ApkParser(pkg_name=args["pkg_name"])
        del args["pkg_name"]
    else:
        print(action)
        not_found()

    return getattr(apk_parser, action, not_found), args


def is_not_installed(command: str) -> bool:
    """Check if a command is installed.

    Args:
        command (str): The command to check.

    Returns:
        bool: True if the command is not installed, False otherwise.
    """
    return not shutil.which(command)


def locate(command: str, use_path=False) -> Optional[Path]:
    """Locate a command.
    Also check if this is a file.

    Args:
        command (str): The command to locate.
        use_path (bool): If the command could be searched in path.

    Returns:
        Path: The path of the command if found, None otherwise.
    """

    cs_path = PATHS

    if use_path:
        cs_path += os.environ.get("path", "").split(os.pathsep)

    cs_path = (os.pathsep).join(cs_path)

    is_windows = sys.platform == "win32" and "." in Path(command).name

    if is_windows:
        # Hacky way to find any file in PATH using shutil.which
        tmp = os.environ.get("PATHEXT", None)
        os.environ["PATHEXT"] = command.split(".")[-1] + ";" + tmp

    path = shutil.which(command, path=cs_path)

    if is_windows:
        if tmp:
            os.environ["PATHEXT"] = tmp  # restore PATHEXT
        else:
            del os.environ["PATHEXT"]

    if path and Path(path).is_file():
        return Path(path)
    return None


def update_perms():
    """Update the permissions of the apk.py home directory.
    """
    if get_os() == "Linux" and APK_PY_HOME.is_dir():
        run(f"chmod 705 -R {APK_PY_HOME}")


def wget(path: Path, url: str):
    """Basic wget implementation using requests.

    Args:
        path (Path): The path to save the file.
        url (str): The url to download.
    """
    # with Progress() as progress:
    response = requests.request(
        method="GET", url=url, stream=True, timeout=10)
    # task = progress.add_task(path.name, total=int(
    # response.headers.get("Content-Length", 0)))
    task = int(response.headers.get("Content-Length", 0))
    sum_size = 0

    with open(path, mode="wb") as file:
        for data in response.iter_content(chunk_size=4096):
            if task > 0:
                print(f"\rWritting... {round(100*sum_size/task)}%", end="")
            else:
                print(f"\rWritting... {sum_size}/?", end="")
            sum_size += 4096
            file.write(data)
            # progress.update(task, advance=len(data))
        # progress.stop()
    print("")
    update_perms()


def run(cmd: str) -> None:
    """Run a command.

    Exit if the command failed.

    Args:
        cmd (str): The command to run.
    """
    try:
        print_(f"> {cmd}")
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as exception:
        print("[>] Sorry!")
        print(f"[!] Command failed: {cmd}")
        print_(exception.stdout.decode("utf-8"))
        print_(exception.stderr.decode("utf-8"))
        # embed()
        print("[>] Bye!")


def print_(text: str) -> None:
    """Print a text if DEBUG.
    """
    if DEBUG:
        print(text)


__version__ = "1.0.6"
DEBUG = False

ARCHS = {
    "arm": "armeabi-v7a", "arm64": "arm64-v8a",
    "x86": "x86", "x86_64": "x86_64"
}
SUPPORTED_ARCH = tuple(ARCHS.keys())

APKEDITOR_VER = "1.2.9"
APKTOOL_VER = "2.7.0"
BUILDTOOLS_VER = "33.0.2"
GADGET_VER = "16.1.3"

APK_PY_HOME = Path.home() / ".apk.py"
SDK_ROOT = APK_PY_HOME / "sdk_root"

PATHS = [str(path) for path in {
    "apktool": APK_PY_HOME,
    "build-tools": SDK_ROOT / "build-tools" / BUILDTOOLS_VER
}.values()]


def not_found(*args, **kwargs):  # pylint: disable=unused-arguments
    raise ValueError("Not found!")


def main():
    """Main basic entry point."""

    args = parse_args()
    args_dict = vars(args)

    apk_parser, args_ = get_parser(args_dict)
    apk_parser(**args_)


if __name__ == "__main__":
    main()
