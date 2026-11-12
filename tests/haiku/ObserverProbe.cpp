/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */

// Sends bad requests to app_server's screen observer and checks that it
// refuses them: a bytes-per-row value whose product with the height wraps
// in 32 bits, and an area that shrank after app_server cloned it.
// Build: g++ -o ObserverProbe ObserverProbe.cpp -lbe
//	-I/boot/system/develop/headers/private/app


#include <Application.h>
#include <OS.h>
#include <Screen.h>

#include <AppServerLink.h>

#include <stdio.h>


enum {
	kStart	= 'RSos',
	kStop	= 'RSoe',
	kRead	= 'RSor',
};


static int sFailures = 0;


static int32
Read(area_id area, int32 bytesPerRow)
{
	BPrivate::AppServerLink link;
	link.StartMessage(kRead);
	link.Attach<area_id>(area);
	link.Attach<int32>(bytesPerRow);
	int32 code;
	if (link.FlushWithReply(code) != B_OK)
		return B_ERROR;
	return code;
}


static void
Expect(const char* what, int32 code, int32 expected)
{
	bool ok = code == expected;
	printf("%s: %s (0x%" B_PRIx32 ")\n", what, ok ? "pass" : "FAIL", code);
	if (!ok)
		sFailures++;
}


int
main()
{
	BApplication app("application/x-vnd.RenkuOS-ObserverProbe");
	BRect frame = BScreen().Frame();
	int32 width = frame.IntegerWidth() + 1;
	int32 height = frame.IntegerHeight() + 1;

	BPrivate::AppServerLink link;
	link.StartMessage(kStart);
	int32 code;
	if (link.FlushWithReply(code) != B_OK || code != B_OK) {
		printf("no screen observer\n");
		return 1;
	}

	size_t full = ((size_t)width * 4 * height + B_PAGE_SIZE - 1)
		& ~(size_t)(B_PAGE_SIZE - 1);
	void* address;
	area_id area = create_area("probe", &address, B_ANY_ADDRESS, full,
		B_NO_LOCK, B_READ_AREA | B_WRITE_AREA | B_CLONEABLE_AREA);
	Expect("read into a full-size area", Read(area, width * 4), B_OK);

	// bytesPerRow * height wraps to a small number in 32 bits.
	int32 wrapping = (int32)((0x100000000ULL + B_PAGE_SIZE) / height + 1);
	Expect("bytes per row that wraps", Read(area, wrapping),
		B_MISMATCHED_VALUES);

	// Shrink the area app_server has already cloned.
	resize_area(area, B_PAGE_SIZE);
	Expect("read into a shrunk area", Read(area, width * 4),
		B_MISMATCHED_VALUES);

	// An area that is not cloneable.
	area_id plain = create_area("probe plain", &address, B_ANY_ADDRESS,
		full, B_NO_LOCK, B_READ_AREA | B_WRITE_AREA);
	Expect("area that is not cloneable", Read(plain, width * 4),
		B_BAD_VALUE);

	link.StartMessage(kStop);
	link.FlushWithReply(code);
	printf("%d failed\n", sFailures);
	return sFailures == 0 ? 0 : 1;
}
