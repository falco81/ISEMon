# Growing the root filesystem after enlarging the disk in VMware (AlmaLinux 9)

Applies to: AlmaLinux 9, root on **ext4 without LVM**, GPT + UEFI, with the disk
already enlarged in VMware.

The whole procedure runs **while the system is up**. A reboot is needed only at the
end, and only to confirm the `resume=` parameter.

---

## 0. Preparation

**Take a snapshot of the VM in VMware.** This procedure deletes and re-creates the
swap partition. Without a snapshot you have nothing to fall back to.

Save the starting state, which you will need if something goes wrong:

```bash
lsblk
cat /etc/fstab
sgdisk -p /dev/sda
blkid
```

Install the tools:

```bash
dnf install -y gdisk cloud-utils-growpart
```

> **Note:** Throughout this document the disk is `/dev/sda`, root is `sda2` and swap
> is `sda3`. Check the numbers against your own `lsblk` and use yours.

---

## 1. Make the kernel see the new disk size

The kernel does not pick up the new size by itself:

```bash
echo 1 > /sys/class/block/sda/device/rescan
lsblk
```

`lsblk` should now show the new size on the `sda` line. The partitions keep their
old sizes, which is expected.

If the size has not changed, rescan all SCSI hosts:

```bash
for h in /sys/class/scsi_host/host*/scan; do echo "- - -" > "$h"; done
```

---

## 2. Decide: is root the last partition?

```bash
sgdisk -p /dev/sda
```

- **Root is the last partition on the disk:** skip to
  [step 6](#6-grow-the-root-partition-and-filesystem). You do not need steps 3–5.
- **Swap comes after root** (typical for an Anaconda install): the free space is
  behind the swap partition, so `growpart` has no room to grow into. Continue with
  step 3.

> **A risk-free alternative:** if it is not specifically `/` that needs the space,
> you can leave the free space as a new partition
> (`sgdisk -n 4:0:0 -t 4:8300 /dev/sda`), create a filesystem on it and mount it
> where the space is really missing (`/var`, `/data`). No partition is removed.

---

## 3. Move swap to the end of the disk

Turn swap off:

```bash
swapoff -a
```

Delete the old swap partition and create a new one at the very end of the disk:

```bash
sgdisk -d 3 /dev/sda
sgdisk -n 3:-10G:0 -t 3:8200 -c 3:swap /dev/sda
partprobe /dev/sda
lsblk
```

The negative offset `-10G` means "10 GiB from the end of the disk". This leaves one
contiguous block of free space between root and the new swap. Adjust the size to
suit.

`sgdisk` may print `Warning: The kernel is still using the old partition table`.
You can ignore it, because `partprobe` takes care of it.

---

## 4. The new swap and its UUID

```bash
mkswap /dev/sda3
blkid /dev/sda3
```

**Write down the new UUID.** The new partition has a different UUID from the old
one, and two places refer to it: `/etc/fstab` and `resume=` in the kernel
parameters.

---

## 5. Put the new UUID into fstab

Replace the old UUID with the new one (use your own values):

```bash
sed -i 's/OLD-UUID/NEW-UUID/' /etc/fstab
grep swap /etc/fstab
systemctl daemon-reload
swapon -a
swapon --show
free -h
```

**Do not skip `systemctl daemon-reload`.** Systemd generated a `.device` unit for
the old UUID from the old fstab. Without the reload, the system would wait 90
seconds at boot for a device that no longer exists.

`swapon --show` should list `/dev/sda3`.

---

## 6. Grow the root partition and filesystem

```bash
growpart /dev/sda 2
resize2fs /dev/sda2
df -h /
```

The space between `/dev/sda` and `2` is intentional: `growpart` takes the device
and the partition number as two separate arguments.

ext4 can be resized online while root is mounted, so nothing has to be unmounted.

---

## 7. Fix the `resume=` parameter (hibernation)

If swap was given as `resume=`, it has to be fixed in **two places**. AlmaLinux 9
uses BLS (Boot Loader Specification), so the current kernel command line is read
from `/boot/loader/entries/*.conf`, not from `/etc/default/grub`.

Check whether this applies to you:

```bash
grep -r resume /etc/default/grub /etc/dracut.conf.d/ 2>/dev/null
```

**a) Existing kernels (the BLS entries), with grubby:**

```bash
grubby --update-kernel=ALL \
  --remove-args="resume=UUID=OLD-UUID" \
  --args="resume=UUID=NEW-UUID"
```

**b) The template for future kernels:**

```bash
sed -i 's/resume=UUID=OLD-UUID/resume=UUID=NEW-UUID/' /etc/default/grub
grep resume /etc/default/grub
```

**c) Regenerate the initramfs:**

```bash
dracut -f --regenerate-all
```

---

## 8. Check before rebooting

```bash
grubby --info=ALL | grep -E '^(kernel|args)'
```

**Every** kernel, the rescue kernel included, should have the new UUID in `args`.

> At this point `cat /proc/cmdline` still shows the old UUID, and that is fine.
> `/proc/cmdline` only records what the running kernel was started with, and it
> does not change while the system runs.

---

## 9. Reboot and final check

```bash
reboot
```

After the system is back up:

```bash
cat /proc/cmdline    # should contain resume=UUID=NEW-UUID
swapon --show        # swap is up on /dev/sda3
df -h /              # the new size of root
lsblk
```

You are done when the boot had no 90-second delays and all three outputs are
right. You can then delete the snapshot in VMware. Do not keep it around for long:
its delta file keeps growing and in time it starts to slow down disk I/O.

---

## Notes for next time

- After this procedure the disk is full up to the swap partition at the end. The
  next time you grow the disk you will face the same steps.
- If the disk is grown regularly, consider converting root to LVM. Then growing it
  is just `lvextend -r -l +100%FREE /dev/vg/root`, with no partitions to move.
- GPT keeps a backup header at the end of the disk, and after the disk grows it is
  in the wrong place. `growpart` and `sgdisk` handle this by themselves; `parted`
  would show a warning about it.

---

## Quick command summary

```bash
# 0. take a snapshot in VMware first!
dnf install -y gdisk cloud-utils-growpart

# 1. rescan the disk
echo 1 > /sys/class/block/sda/device/rescan

# 3. move swap to the end
swapoff -a
sgdisk -d 3 /dev/sda
sgdisk -n 3:-10G:0 -t 3:8200 -c 3:swap /dev/sda
partprobe /dev/sda

# 4.-5. new swap + fstab
mkswap /dev/sda3
blkid /dev/sda3
sed -i 's/OLD-UUID/NEW-UUID/' /etc/fstab
systemctl daemon-reload
swapon -a

# 6. root
growpart /dev/sda 2
resize2fs /dev/sda2

# 7. resume=
grubby --update-kernel=ALL \
  --remove-args="resume=UUID=OLD-UUID" \
  --args="resume=UUID=NEW-UUID"
sed -i 's/resume=UUID=OLD-UUID/resume=UUID=NEW-UUID/' /etc/default/grub
dracut -f --regenerate-all

# 8.-9.
grubby --info=ALL | grep -E '^(kernel|args)'
reboot
```
