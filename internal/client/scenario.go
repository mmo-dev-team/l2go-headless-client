// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"encoding/binary"
	"errors"
	"strconv"
	"time"

	l2net "github.com/mmo-dev-team/l2go-headless-client/internal/net"
)

type point struct{ x, y int32 }

const radius = 3000

// StarterClasses are the nine-base classes.
// Scenario A creates one per account (driven by thread index).
var StarterClasses = []int32{0, 10, 18, 25, 31, 38, 44, 49, 53}

var townCenter = map[int32]point{
	0:  {-71338, 258271},  // Human Fighter
	10: {-90875, 248162},  // Human Mystic
	18: {46045, 41251},    // Elf
	25: {46045, 41251},    // Elf Mystic
	31: {28295, 11063},    // Dark Elf
	38: {28295, 11063},    // Dark Elf Mystic
	44: {-56733, -113459}, // Orc
	49: {-56733, -113459}, // Orc Mystic
	53: {108644, -173947}, // Dwarf
}

// RunScenario dispatches a named functional scenario. class selects the base class
// for create-based scenarios (driven by the caller from the thread index).
func (c *Client) RunScenario(name string, class int32) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("scenario panic")
		}
	}()
	switch name {
	case "A", "a":
		return c.ScenarioCreateAndEnter(class)
	case "B", "b":
		return c.ScenarioMultiChar()
	case "C", "c", "D", "d":
		return c.ScenarioEnterWorld(class)
	default:
		return errors.New("unknown scenario: " + name)
	}
}

// ScenarioEnterWorld creates a character if needed, enters the world,
// and asserts the server delivers an inventory with equippable gear.
func (c *Client) ScenarioEnterWorld(class int32) error {
	info, err := c.HandshakeToLobby()
	if err != nil {
		return err
	}
	if info.CharacterCount == 0 {
		if cErr := c.createNamedCharacter(sanitizeName(c.account), class); cErr != nil {
			return cErr
		}
	}

	objId, _, x, y, z, sErr := c.selectAndEnter(0)
	if sErr != nil {
		return sErr
	}
	c.objectId, c.x, c.y, c.z = objId, x, y, z

	// Read the post-enter burst until the inventory (ItemList) arrives or time out.
	_ = c.gsConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer func() { _ = c.gsConn.SetReadDeadline(time.Time{}) }()

	gotItemList := false
	gearCount := 0
	for !gotItemList {
		data, rErr := c.recvGS()
		if rErr != nil {
			return errors.New("scenario C: no ItemList within window after enter: " + rErr.Error())
		}
		if len(data) == 0 {
			continue
		}
		c.logPacket("S2C", "GS:postEnter", data) // surface the post-enter packet stream
		switch data[0] {
		case l2net.OpGSItemList:
			// The server sends two item lists (sendType 1 then 2); only sendType 2
			// carries the parseable item payload, so wait for it before counting gear.
			if len(data) >= 2 && data[1] == 2 {
				if items := l2net.ExtractEquippableItems(data); len(items) > 0 {
					c.inventory = items
					gearCount = len(items)
				}
				gotItemList = true
			}
		case l2net.OpGSDie:
			if len(data) >= 5 && binary.LittleEndian.Uint32(data[1:5]) == c.objectId {
				return errors.New("scenario C: character died on entering the world")
			}
		}
	}

	// If equippable gear was delivered, fire one equip action.
	if len(c.inventory) > 0 {
		payload := c.gsWriter.Prepare(15)
		n := l2net.EncodeGSUseItemTo(c.inventory[0], false, payload)
		if eErr := c.sendGS(payload, n); eErr != nil {
			return errors.New("scenario D: equip action failed: " + eErr.Error())
		}
	}

	c.log.Log(c.account, "scenario C/D PASS: entered at ("+strconv.Itoa(int(x))+","+
		strconv.Itoa(int(y))+"), ItemList received, equippable="+strconv.Itoa(gearCount))
	return nil
}

// ScenarioMultiChar Verifies the multi-character slot pipeline on one
// account: create three characters of different classes, then delete / restore /
// select by slot index — asserting each operation hits the intended slot.
func (c *Client) ScenarioMultiChar() error {
	info, err := c.HandshakeToLobby()
	if err != nil {
		return err
	}

	base := sanitizeName(c.account)
	classes := []int32{0, 10, 18} // slot 0=human fighter, 1=human mystic, 2=elf fighter
	for i := int(info.CharacterCount); i < len(classes); i++ {
		if cErr := c.createNamedCharacter(slotName(base, i), classes[i]); cErr != nil {
			return cErr
		}
	}

	// Delete slot 1 — the server replies with a refreshed selection list.
	if err = c.sendSlotOp(l2net.EncodeGSCharacterDeleteTo, 1); err != nil {
		return err
	}
	if info, err = c.recvSelectionInfo(); err != nil {
		return err
	}
	if int(info.CharacterCount) < 3 {
		return errors.New("scenario B: expected 3 characters after delete, got " +
			strconv.Itoa(int(info.CharacterCount)))
	}
	if info.Characters[1].DeleteTimer <= 0 {
		return errors.New("scenario B: slot 1 was not marked for deletion")
	}
	if info.Characters[0].DeleteTimer != 0 || info.Characters[2].DeleteTimer != 0 {
		return errors.New("scenario B: delete hit the wrong slot (0 or 2 marked)")
	}

	// Restore slot 1 — refreshed list again.
	if err = c.sendSlotOp(l2net.EncodeGSCharacterRestoreTo, 1); err != nil {
		return err
	}
	if info, err = c.recvSelectionInfo(); err != nil {
		return err
	}
	if info.Characters[1].DeleteTimer != 0 {
		return errors.New("scenario B: restore did not clear slot 1's delete flag")
	}

	// Select slot 1 — must return the slot-1 character (class 10), not slot 0.
	_, gotClass, _, _, _, sErr := c.selectAndEnter(1)
	if sErr != nil {
		return sErr
	}
	if gotClass != uint32(classes[1]) {
		return errors.New("scenario B: select slot 1 returned class " +
			strconv.Itoa(int(gotClass)) + ", want " + strconv.Itoa(int(classes[1])))
	}

	c.log.Log(c.account, "scenario B PASS: 3 chars, delete/restore/select by slot correct")
	return nil
}

// sendSlotOp sends a lobby slot operation (delete/restore) for the given slot.
func (c *Client) sendSlotOp(enc func(int32, []byte) int, slot int32) error {
	payload := c.gsWriter.Prepare(16)
	n := enc(slot, payload)
	return c.sendGS(payload, n)
}

// recvSelectionInfo reads the next packet and decodes it as a character-selection list.
func (c *Client) recvSelectionInfo() (*l2net.CharSelectionInfo, error) {
	data, err := c.recvGS()
	if err != nil {
		return nil, err
	}
	if data[0] != l2net.OpGSCharSelectionInfo {
		return nil, errors.New("scenario: expected selection info, got opcode " +
			strconv.Itoa(int(data[0])))
	}
	return l2net.DecodeCharSelectionInfo(data)
}

// slotName builds a unique, valid (<=16) character name for the given slot.
func slotName(base string, slot int) string {
	if len(base) > 14 {
		base = base[:14]
	}
	return base + strconv.Itoa(slot)
}

// ScenarioCreateAndEnter creates a character of the given base class on
// this account, selects it, enters the world, and asserts it spawned in the right village.
// Returns an error describing the first failed assertion.
func (c *Client) ScenarioCreateAndEnter(class int32) error {
	info, err := c.HandshakeToLobby()
	if err != nil {
		return err
	}

	if info.CharacterCount == 0 {
		if cErr := c.createNamedCharacter(sanitizeName(c.account), class); cErr != nil {
			return cErr
		}
	}

	objId, gotClass, x, y, z, sErr := c.selectAndEnter(0)
	if sErr != nil {
		return sErr
	}
	c.objectId, c.classId, c.x, c.y, c.z = objId, gotClass, x, y, z

	tc, ok := townCenter[class]
	if !ok {
		return errors.New("scenario A: no town reference for class " + strconv.Itoa(int(class)))
	}
	dx, dy := x-tc.x, y-tc.y
	if dx*dx+dy*dy > radius*radius {
		return errors.New("scenario A: class " + strconv.Itoa(int(class)) +
			" spawned at (" + strconv.Itoa(int(x)) + "," + strconv.Itoa(int(y)) +
			") — not near its village (" + strconv.Itoa(int(tc.x)) + "," + strconv.Itoa(int(tc.y)) + ")")
	}

	c.log.Log(c.account, "scenario A PASS: class "+strconv.Itoa(int(class))+
		" created + entered at ("+strconv.Itoa(int(x))+","+strconv.Itoa(int(y))+")")
	return nil
}

// createNamedCharacter sends a create request for the class+name and waits for the result.
func (c *Client) createNamedCharacter(name string, class int32) error {
	payload := c.gsWriter.Prepare(100)
	n := l2net.EncodeGSCharacterCreateTo(name, raceForClass(class), false, class, 0, 0, 0, payload)
	c.logPacket("C2S", "GS:CharacterCreate", payload[:n])
	if err := c.sendGS(payload, n); err != nil {
		return err
	}

	data, err := c.recvGS()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return errors.New("scenario: empty create response")
	}
	switch data[0] {
	case l2net.OpGSCharCreateSuccess:
		return nil
	case l2net.OpGSCharCreateFail:
		return errors.New("scenario: character create failed for class " + strconv.Itoa(int(class)))
	default:
		return errors.New("scenario: unexpected create response opcode")
	}
}

// selectAndEnter selects the character at slot and enters the world, returning the
// spawn coordinates from CharSelected.
func (c *Client) selectAndEnter(slot int32) (objId, class uint32, x, y, z int32, err error) {
	payload := c.gsWriter.Prepare(30)
	n := l2net.EncodeGSCharacterSelectTo(slot, payload)
	c.logPacket("C2S", "GS:CharacterSelect", payload[:n])
	if err = c.sendGS(payload, n); err != nil {
		return
	}

	for {
		var data []byte
		if data, err = c.recvGS(); err != nil {
			return
		}
		if len(data) == 0 {
			continue // empty keep-alive / framing packet
		}
		if data[0] == l2net.OpGSCharSelected {
			objId, class, x, y, z, err = l2net.DecodeCharSelected(data)
			break
		}
	}
	if err != nil {
		return
	}

	payload = c.gsWriter.Prepare(110)
	n = l2net.EncodeGSEnterWorldTo(payload)
	c.logPacket("C2S", "GS:EnterWorld", payload[:n])
	if err = c.sendGS(payload, n); err != nil {
		return
	}
	c.State = StateGSLoggedIn
	return
}

// sanitizeName derives a valid (alphanumeric, <=16) character name from the account.
func sanitizeName(account string) string {
	var b []byte
	for i := 0; i < len(account) && len(b) < 16; i++ {
		ch := account[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			b = append(b, ch)
		}
	}
	if len(b) < 3 {
		return "BotTestPlayer"
	}
	return string(b)
}

// raceForClass maps a base class to its race id for the create packet.
func raceForClass(class int32) int32 {
	switch class {
	case 0, 10:
		return 0 // Human
	case 18, 25:
		return 1 // Elf
	case 31, 38:
		return 2 // Dark Elf
	case 44, 49:
		return 3 // Orc
	default:
		return 4 // Dwarf
	}
}
