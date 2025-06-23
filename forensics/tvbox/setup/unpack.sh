
#!/bin/bash

OUTPUT_FOLDER="output"
FIRMWARE_IMAGE_FILE="$1"

CHIP_CODE="RK322H"

CMD_RKIMAGEMAKER_BIN="rkImageMaker"
CMD_RKIMAGEMAKER_URL="https://github.com/khadas/android_RKTools/raw/refs/heads/khadas-edge-nougat-v1.0/linux/Linux_Pack_Firmware/rockdev/rkImageMaker"

CMD_AFPTOOL_BIN="afptool"
CMD_AFPTOOL_URL="https://github.com/khadas/android_RKTools/raw/refs/heads/khadas-edge-nougat-v1.0/linux/Linux_Pack_Firmware/rockdev/afptool"

CMD_SIMG2IMG_BIN="simg2img"
CMD_IMG2SIMG_BIN="img2simg"
CMD_SIMG2IMG_GIT="https://github.com/anestisb/android-simg2img"

CMD_LPUNPACK_BIN="lpunpack"
CMD_LPUNPACK_URL="https://github.com/Exynos-nibba/lpunpack-lpmake-mirror/raw/refs/heads/Linux-debian/binary/lpunpack"

CMD_LPMAKE_BIN="lpmake"
CMD_LPMAKE_URL="https://github.com/Exynos-nibba/lpunpack-lpmake-mirror/raw/refs/heads/Linux-debian/binary/lpmake"

APT_UPDATE_DONE=0

check_and_install() {
    local cmd="$1"
    local pkg="$2"

    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "Command '${cmd}' not found. Installing '${pkg}'..."
        if [ $APT_UPDATE_DONE -eq 0 ]; then
            sudo apt-get update
            APT_UPDATE_DONE=1
        fi
        sudo apt-get install -y "${pkg}"
    fi
}

check_and_install_pkg() {
    local pkg="$1"

    if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
        echo "Package '${pkg}' not installed. Installing..."
        if [ $APT_UPDATE_DONE -eq 0 ]; then
            sudo apt-get update
            APT_UPDATE_DONE=1
        fi
        sudo apt-get install -y "${pkg}"
    fi
}

ask_user() {
    local name="$1"
    local var_name="$2"
    local default="${3:-N}"  # Default is "N" unless specified

    local prompt
    if [[ "$default" =~ ^[Yy]$ ]]; then
        prompt="${name} [Y/n]: "
    else
        prompt="${name} [y/N]: "
    fi

    read -p "$prompt" response

    # Use default if input is empty
    if [[ -z "$response" ]]; then
        response="$default"
    fi

    if [[ "$response" =~ ^[Yy]$ ]]; then
        eval "${var_name}=1"
    else
        eval "${var_name}=0"
    fi
}

size_to_bytes() {
    local size_str=$1
    local num=${size_str%[KMGTP]*}   # number part
    local unit=${size_str##*[0-9]}   # unit part (last char)
    case $unit in
        K|k) echo $((num * 1024)) ;;
        M|m) echo $((num * 1024**2)) ;;
        G|g) echo $((num * 1024**3)) ;;
        T|t) echo $((num * 1024**4)) ;;
        P|p) echo $((num * 1024**5)) ;;
        *)   echo "$num" ;;  # no unit, assume bytes
    esac
}



# Download commands if not exist
if [ ! -f "${CMD_RKIMAGEMAKER_BIN}" ]; then
    check_and_install wget wget
    wget -O "${CMD_RKIMAGEMAKER_BIN}" "${CMD_RKIMAGEMAKER_URL}" || {
        echo "Failed to download ${CMD_RKIMAGEMAKER_BIN} from ${CMD_RKIMAGEMAKER_URL}"
        exit 1
    }
fi
if [ ! -f "${CMD_AFPTOOL_BIN}" ]; then
    check_and_install wget wget
    wget -O "${CMD_AFPTOOL_BIN}" "${CMD_AFPTOOL_URL}" || {
        echo "Failed to download ${CMD_AFPTOOL_BIN} from ${CMD_AFPTOOL_URL}"
        exit 1
    }
fi
if [ ! -f "${CMD_SIMG2IMG_BIN}" ] || [ ! -f "${CMD_IMG2SIMG_BIN}" ]; then
    if [ ! -d "android-simg2img" ]; then
        check_and_install git git
        git clone "${CMD_SIMG2IMG_GIT}" "android-simg2img"
    fi

    if [ ! -f "android-simg2img/simg2img" ] || [ ! -f "android-simg2img/img2simg" ]; then
        check_and_install make build-essential
        check_and_install_pkg libz-dev
        cd "android-simg2img"
        make
        cd ..
    fi

    mv "android-simg2img/simg2img" "${CMD_SIMG2IMG_BIN}"
    mv "android-simg2img/img2simg" "${CMD_IMG2SIMG_BIN}"
    rm -rf "android-simg2img"
fi

if [ ! -f "${CMD_LPUNPACK_BIN}" ]; then
    check_and_install wget wget
    wget -O "${CMD_LPUNPACK_BIN}" "${CMD_LPUNPACK_URL}" || {
        echo "Failed to download ${CMD_LPUNPACK_BIN} from ${CMD_LPUNPACK_URL}"
        exit 1
    }
fi
if [ ! -f "${CMD_LPMAKE_BIN}" ]; then
    check_and_install wget wget
    wget -O "${CMD_LPMAKE_BIN}" "${CMD_LPMAKE_URL}" || {
        echo "Failed to download ${CMD_LPMAKE_BIN} from ${CMD_LPMAKE_URL}"
        exit 1
    }
fi


# Check if input file exists
[ -f "${FIRMWARE_IMAGE_FILE}" ] || {
    echo "Input file was not found"
    exit 1
}
[[ "${FIRMWARE_IMAGE_FILE}" == *.img || "${FIRMWARE_IMAGE_FILE}" == *.IMG ]] || {
    echo "Invalid input file"
    exit 1
}

# Prepare output folder
mkdir -p "${OUTPUT_FOLDER}"

# Unpack image
SKIP_IMAGE_UNPACKING=0
if [ -f "${OUTPUT_FOLDER}/boot.bin" ] && [ -f "${OUTPUT_FOLDER}/firmware.img" ]; then
    echo "RK image is probably already unpacked"
    ask_user "Do you want to skip image unpacking?" "SKIP_IMAGE_UNPACKING" "Y"
fi
if [ $SKIP_IMAGE_UNPACKING -eq 0 ]; then
    echo "Unpacking RK image ..."
    "./$CMD_RKIMAGEMAKER_BIN" -unpack "$1" "${OUTPUT_FOLDER}"
    # this will generate:
    #   output/boot.bin
    #   output/firmware.img
fi


# Unpack firmware
SKIP_FIRMWARE_UNPACKING=0
if [ -f "${OUTPUT_FOLDER}/package-file" ] && [ -f "${OUTPUT_FOLDER}/Image/super.img" ]; then
    echo "Firmware is probably already unpacked"
    ask_user "Do you want to skip firmware unpacking?" "SKIP_FIRMWARE_UNPACKING" "Y"
fi
if [ $SKIP_FIRMWARE_UNPACKING -eq 0 ]; then
    echo "Unpacking firmware ..."
    "./$CMD_AFPTOOL_BIN" -unpack "${OUTPUT_FOLDER}/firmware.img" "${OUTPUT_FOLDER}"
    # this will generate:
    #   output/MiniLoaderAll.bin <-- this is a bug, this file should be moved inside the Image
    #   output/package-file
    #   output/parameter.txt <-- this is a bug, this file should be moved inside the Image
    #   output/Image/MiniLoaderAll.bin
    #   output/Image/parameter.txt
    #   output/Image/trust.img
    #   output/Image/uboot.img
    #   output/Image/misc.img
    #   output/Image/boot.img
    #   output/Image/dtbo.img
    #   output/Image/vbmeta.img
    #   output/Image/recovery.img
    #   output/Image/baseparameter.img
    #   output/Image/super.img
fi


# Unpack super
mkdir -p "${OUTPUT_FOLDER}/Image/super"

SKIP_SUPER_UNPACKING=0
if [ -f "${OUTPUT_FOLDER}/Image/super/system.img" ] && [ -f "${OUTPUT_FOLDER}/Image/super/product.img" ] && [ -f "${OUTPUT_FOLDER}/Image/super/vendor.img" ]; then
    echo "Super is probably already unpacked"
    ask_user "Do you want to skip super unpacking?" "SKIP_SUPER_UNPACKING" "Y"
fi
if [ $SKIP_SUPER_UNPACKING -eq 0 ]; then
    "./$CMD_SIMG2IMG_BIN" "${OUTPUT_FOLDER}/Image/super.img" "${OUTPUT_FOLDER}/Image/super/super.ext4.img"
    "./$CMD_LPUNPACK_BIN" "${OUTPUT_FOLDER}/Image/super/super.ext4.img" "${OUTPUT_FOLDER}/Image/super"
    rm "${OUTPUT_FOLDER}/Image/super/super.ext4.img"
fi

# Resize system
echo "Resizing system image ..."
NEW_SYSTEM_SIZE_STR=2G

OLD_SYSTEM_SIZE=$(stat -c%s "${OUTPUT_FOLDER}/Image/super/system.img")
NEW_SYSTEM_SIZE=$(size_to_bytes "$NEW_SYSTEM_SIZE_STR")
if [ "$OLD_SYSTEM_SIZE" -lt "$NEW_SYSTEM_SIZE" ]; then
    echo $OLD_SYSTEM_SIZE ">" $NEW_SYSTEM_SIZE
    echo fallocate -l "${NEW_SYSTEM_SIZE_STR}" "${OUTPUT_FOLDER}/Image/super/system.img"
    fallocate -l "${NEW_SYSTEM_SIZE_STR}" "${OUTPUT_FOLDER}/Image/super/system.img"
    resize2fs "${OUTPUT_FOLDER}/Image/super/system.img" "${NEW_SYSTEM_SIZE_STR}"
else
    echo "System image is $NEW_SYSTEM_SIZE_STR or bigger, no resize needed."
fi

# Mount system for file editing
echo "Mounting system image ..."
mkdir -p "${OUTPUT_FOLDER}/Image/super/system_rootfs"
sudo mount -t ext4 -o loop "${OUTPUT_FOLDER}/Image/super/system.img" "${OUTPUT_FOLDER}/Image/super/system_rootfs"

echo "You can now edit system files ..."
read -p "When done editing files, press Enter to continue..."
# use sudo to copy files and check if you need to also change the permissions

# sudo cp /media/sf_Projects/AndroidTV/app-release.apk /media/sf_Projects/AndroidTV/output/Image/super/system_rootfs/system/priv-app/TVUpdater/TVUpdater.apk
# sudo chmod 644 /media/sf_Projects/AndroidTV/output/Image/super/system_rootfs/system/priv-app/TVUpdater/TVUpdater.apk

echo "Unmounting system image ..."
sudo umount "${OUTPUT_FOLDER}/Image/super/system_rootfs"
rm -r "${OUTPUT_FOLDER}/Image/super/system_rootfs"

# Prepare system image
echo "Checking system image and removing empty space ..."
e2fsck -yf "${OUTPUT_FOLDER}/Image/super/system.img"
resize2fs -M "${OUTPUT_FOLDER}/Image/super/system.img"
e2fsck -yf "${OUTPUT_FOLDER}/Image/super/system.img"

# Convert to Android sparse image
echo "Converting images to Android sparse image format ..."
"./$CMD_IMG2SIMG_BIN" "${OUTPUT_FOLDER}/Image/super/odm.img" "${OUTPUT_FOLDER}/Image/super/odm.simg"
"./$CMD_IMG2SIMG_BIN" "${OUTPUT_FOLDER}/Image/super/product.img" "${OUTPUT_FOLDER}/Image/super/product.simg"
"./$CMD_IMG2SIMG_BIN" "${OUTPUT_FOLDER}/Image/super/system_ext.img" "${OUTPUT_FOLDER}/Image/super/system_ext.simg"
"./$CMD_IMG2SIMG_BIN" "${OUTPUT_FOLDER}/Image/super/system.img" "${OUTPUT_FOLDER}/Image/super/system.simg"
"./$CMD_IMG2SIMG_BIN" "${OUTPUT_FOLDER}/Image/super/vendor.img" "${OUTPUT_FOLDER}/Image/super/vendor.simg"

# Get actual sizes (in bytes)
NEW_SYSTEM_SIZE=$(stat -c%s "${OUTPUT_FOLDER}/Image/super/system.img")
NEW_SYSTEM_EXT_SIZE=$(stat -c%s "${OUTPUT_FOLDER}/Image/super/system_ext.img")
NEW_PRODUCT_SIZE=$(stat -c%s "${OUTPUT_FOLDER}/Image/super/product.img")
NEW_VENDOR_SIZE=$(stat -c%s "${OUTPUT_FOLDER}/Image/super/vendor.img")
NEW_ODM_SIZE=$(stat -c%s "${OUTPUT_FOLDER}/Image/super/odm.img")

NEW_GROUP_SIZE=$((NEW_SYSTEM_SIZE + NEW_SYSTEM_EXT_SIZE + NEW_PRODUCT_SIZE + NEW_VENDOR_SIZE + NEW_ODM_SIZE))
NEW_SUPER_SIZE=$((NEW_GROUP_SIZE + 4 * 65536 + 64 * 1024 * 1024))
# make the size multiple of the block size 
BLOCK_SIZE=4096
NEW_SUPER_SIZE=$(( (NEW_SUPER_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE ))

# Pack an updated super image
echo "Packing an updated super image ..."
"./$CMD_LPMAKE_BIN" \
  --metadata-size 65536 \
  --super-name super \
  --metadata-slots 1 \
  --device super:$NEW_SUPER_SIZE \
  --group main:$NEW_GROUP_SIZE \
  --partition system:readonly:$NEW_SYSTEM_SIZE:main --image "system=${OUTPUT_FOLDER}/Image/super/system.simg" \
  --partition system_ext:readonly:$NEW_SYSTEM_EXT_SIZE:main --image "system_ext=${OUTPUT_FOLDER}/Image/super/system_ext.simg" \
  --partition product:readonly:$NEW_PRODUCT_SIZE:main --image "product=${OUTPUT_FOLDER}/Image/super/product.simg" \
  --partition vendor:readonly:$NEW_VENDOR_SIZE:main --image "vendor=${OUTPUT_FOLDER}/Image/super/vendor.simg" \
  --partition odm:readonly:$NEW_ODM_SIZE:main --image "odm=${OUTPUT_FOLDER}/Image/super/odm.simg" \
  --sparse \
  --output "${OUTPUT_FOLDER}/Image/super.updated.img"

if [ -f "${OUTPUT_FOLDER}/Image/super.img" ]; then
    echo "Moving original super.img to super.img.backup"
    mv "${OUTPUT_FOLDER}/Image/super.img" "${OUTPUT_FOLDER}/Image/super.img.backup"
fi
mv "${OUTPUT_FOLDER}/Image/super.updated.img" "${OUTPUT_FOLDER}/Image/super.img"

# Repack firmware
SKIP_FIRMWARE_PACKING=0
if [ -f "${OUTPUT_FOLDER}/firmware.img" ]; then
    echo "Firmware is probably already packed"
    ask_user "Do you want to skip firmware packing?" "SKIP_FIRMWARE_PACKING" "Y"
fi
if [ $SKIP_FIRMWARE_PACKING -eq 0 ]; then

    # Fix bugs
    if [ -f "${OUTPUT_FOLDER}/parameter.txt" ]; then
        echo "Moving parameter.txt to the correct location"
        mv "${OUTPUT_FOLDER}/parameter.txt" "${OUTPUT_FOLDER}/Image/parameter.txt"
    fi
    if [ -f "${OUTPUT_FOLDER}/MiniLoaderAll.bin" ]; then
        echo "Moving MiniLoaderAll.bin to the correct location"
        mv "${OUTPUT_FOLDER}/MiniLoaderAll.bin" "${OUTPUT_FOLDER}/Image/MiniLoaderAll.bin"
    fi

    ## Rename old firmware
    if [ -f "${OUTPUT_FOLDER}/firmware.img" ]; then
        echo "Moving original firmware.img to firmware.img.backup"
        mv "${OUTPUT_FOLDER}/firmware.img" "${OUTPUT_FOLDER}/firmware.img.backup"
    fi

    # Pack firmware
    echo "Packing firmware ..."
    "./$CMD_AFPTOOL_BIN" -pack "${OUTPUT_FOLDER}" "${OUTPUT_FOLDER}/firmware.img"
fi

# Repack image
SKIP_IMAGE_PACKING=0
if [ -f "${FIRMWARE_IMAGE_FILE}_updated.img" ]; then
    echo "RK image is probably already packed"
    ask_user "Do you want to skip image packing?" "SKIP_IMAGE_PACKING" "Y"
fi
if [ $SKIP_IMAGE_PACKING -eq 0 ]; then
    echo "Packing RK image ..."
    "./$CMD_RKIMAGEMAKER_BIN" "-$CHIP_CODE" "${OUTPUT_FOLDER}/boot.bin" "${OUTPUT_FOLDER}/firmware.img" "${FIRMWARE_IMAGE_FILE}_updated.img" -os_type:androidos
fi
