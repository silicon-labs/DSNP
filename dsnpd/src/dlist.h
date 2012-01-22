/*
 * Copyright (c) 2011, Adrian Thurston <thurston@complang.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _DLIST_H
#define _DLIST_H

#define BASE_EL(name) name

/* Doubly Linked List */
template <class Element> class DList
{
public:
	/** \brief Initialize an empty list. */
	DList() : head(0), tail(0), listLen(0) {}

	/** 
	 * \brief Perform a deep copy of the list.
	 * 
	 * The elements of the other list are duplicated and put into this list.
	 * Elements are copied using the copy constructor.
	 */
	DList(const DList &other);

	/**
	 * \brief Abandon all elements in the list. 
	 *
	 * List elements are not deleted.
	 */
	~DList() {}

	/**
	 * \brief Perform a deep copy of the list.
	 *
	 * The elements of the other list are duplicated and put into this list.
	 * Each list item is created using the copy constructor. If this list
	 * contains any elements before the copy, they are abandoned.
	 *
	 * \returns A reference to this.
	 */
	DList &operator=(const DList &other);

	/**
	 * \brief Transfer the contents of another list into this list.
	 *
	 * The elements of the other list moved in. The other list will be empty
	 * afterwards.  If this list contains any elements before the copy, they
	 * are abandoned. 
	 */
	void transfer(DList &other);


	void prepend(Element *new_el) { addBefore(head, new_el); }
	void append(Element *new_el)  { addAfter(tail, new_el); }
	void prepend(DList &dl)       { addBefore(head, dl); }
	void append(DList &dl)        { addAfter(tail, dl); }

	void addAfter(Element *prev_el, Element *new_el);
	void addBefore(Element *next_el, Element *new_el);

	void addAfter(Element *prev_el, DList &dl);
	void addBefore(Element *next_el, DList &dl);

	Element *detachFirst()        { return detach(head); }

	Element *detachLast()         { return detach(tail); }

	Element *detach(Element *el);

	void removeFirst()         { delete detach( head ); }

	void removeLast()          { delete detach( tail ); }

	void remove(Element *el)   { delete detach( el ); }
	
	void empty();
	void abandon();

	long length() const { return listLen; }

	Element *head, *tail;

	long listLen;

	long size() const           { return listLen; }

	/* Forward this so a ref can be used. */
	struct Iter;

	/* Class for setting the iterator. */
	struct IterFirst { IterFirst( const DList &l ) : l(l) { } const DList &l; };
	struct IterLast { IterLast( const DList &l ) : l(l) { } const DList &l; };
	struct IterNext { IterNext( const Iter &i ) : i(i) { } const Iter &i; };
	struct IterPrev { IterPrev( const Iter &i ) : i(i) { } const Iter &i; };

	/**
	 * \brief Double List Iterator. 
	 * \ingroup iterators
	 */
	struct Iter
	{
		/* Default construct. */
		Iter() : ptr(0) { }

		/* Construct from a double list. */
		Iter( const DList &dl )      : ptr(dl.head) { }
		Iter( Element *el )          : ptr(el) { }
		Iter( const IterFirst &dlf ) : ptr(dlf.l.head) { }
		Iter( const IterLast &dll )  : ptr(dll.l.tail) { }
		Iter( const IterNext &dln )  : ptr(dln.i.ptr->BASE_EL(next)) { }
		Iter( const IterPrev &dlp )  : ptr(dlp.i.ptr->BASE_EL(prev)) { }

		/* Assign from a double list. */
		Iter &operator=( const DList &dl )     { ptr = dl.head; return *this; }
		Iter &operator=( Element *el )         { ptr = el; return *this; }
		Iter &operator=( const IterFirst &af ) { ptr = af.l.head; return *this; }
		Iter &operator=( const IterLast &al )  { ptr = al.l.tail; return *this; }
		Iter &operator=( const IterNext &an )  { ptr = an.i.ptr->BASE_EL(next); return *this; }
		Iter &operator=( const IterPrev &ap )  { ptr = ap.i.ptr->BASE_EL(prev); return *this; }

		/** \brief Less than end? */
		bool lte() const    { return ptr != 0; }

		/** \brief At end? */
		bool end() const    { return ptr == 0; }

		/** \brief Greater than beginning? */
		bool gtb() const { return ptr != 0; }

		/** \brief At beginning? */
		bool beg() const { return ptr == 0; }

		/** \brief At first element? */
		bool first() const { return ptr && ptr->BASE_EL(prev) == 0; }

		/** \brief At last element? */
		bool last() const  { return ptr && ptr->BASE_EL(next) == 0; }

		/** \brief Implicit cast to Element*. */
		operator Element*() const   { return ptr; }

		/** \brief Dereference operator returns Element&. */
		Element &operator *() const { return *ptr; }

		/** \brief Arrow operator returns Element*. */
		Element *operator->() const { return ptr; }

		/** \brief Move to next item. */
		inline Element *operator++()      { return ptr = ptr->BASE_EL(next); }

		/** \brief Move to next item. */
		inline Element *increment()       { return ptr = ptr->BASE_EL(next); }

		/** \brief Move to next item. */
		inline Element *operator++(int);

		/** \brief Move to previous item. */
		inline Element *operator--()      { return ptr = ptr->BASE_EL(prev); }

		/** \brief Move to previous item. */
		inline Element *decrement()       { return ptr = ptr->BASE_EL(prev); }

		/** \brief Move to previous item. */
		inline Element *operator--(int);

		/** \brief Return the next item. Does not modify this. */
		inline IterNext next() const { return IterNext(*this); }

		/** \brief Return the prev item. Does not modify this. */
		inline IterPrev prev() const { return IterPrev(*this); }

		/** \brief The iterator is simply a pointer. */
		Element *ptr;
	};

	/** \brief Return first element. */
	IterFirst first()  { return IterFirst(*this); }

	/** \brief Return last element. */
	IterLast last()    { return IterLast(*this); }
};

/* Copy constructor, does a deep copy of other. */
template <class Element> DList<Element>::
		DList(const DList<Element> &other) :
			head(0), tail(0), listLen(0)
{
	Element *el = other.head;
	while( el != 0 ) {
		append( new Element(*el) );
		el = el->BASE_EL(next);
	}
}


/* Assignement operator does deep copy. */
template <class Element> DList<Element> &DList<Element>::
		operator=(const DList &other)
{
	Element *el = other.head;
	while( el != 0 ) {
		append( new Element(*el) );
		el = el->BASE_EL(next);
	}
	return *this;
}

template <class Element> void DList<Element>::
		transfer(DList &other)
{
	head = other.head;
	tail = other.tail;
	listLen = other.listLen;

	other.abandon();
}

/*
 * The larger iterator operators.
 */

/* Postfix ++ */
template <class Element> Element *DList<Element>::Iter::
		operator++(int)       
{
	Element *rtn = ptr; 
	ptr = ptr->BASE_EL(next);
	return rtn;
}

/* Postfix -- */
template <class Element> Element *DList<Element>::Iter::
		operator--(int)       
{
	Element *rtn = ptr;
	ptr = ptr->BASE_EL(prev);
	return rtn;
}

/**
 * \brief Insert an element immediately after an element in the list.
 *
 * If prev_el is NULL then new_el is prepended to the front of the list. If
 * prev_el is not in the list or if new_el is already in a list, then
 * undefined behaviour results.
 */
template <class Element> void DList<Element>::
		addAfter(Element *prev_el, Element *new_el)
{
	/* Set the previous pointer of new_el to prev_el. We do
	 * this regardless of the state of the list. */
	new_el->BASE_EL(prev) = prev_el; 

	/* Set forward pointers. */
	if (prev_el == 0) {
		/* There was no prev_el, we are inserting at the head. */
		new_el->BASE_EL(next) = head;
		head = new_el;
	} 
	else {
		/* There was a prev_el, we can access previous next. */
		new_el->BASE_EL(next) = prev_el->BASE_EL(next);
		prev_el->BASE_EL(next) = new_el;
	} 

	/* Set reverse pointers. */
	if (new_el->BASE_EL(next) == 0) {
		/* There is no next element. Set the tail pointer. */
		tail = new_el;
	}
	else {
		/* There is a next element. Set it's prev pointer. */
		new_el->BASE_EL(next)->BASE_EL(prev) = new_el;
	}

	/* Update list length. */
	listLen++;
}

/**
 * \brief Insert an element immediatly before an element in the list.
 *
 * If next_el is NULL then new_el is appended to the end of the list. If
 * next_el is not in the list or if new_el is already in a list, then
 * undefined behaviour results.
 */
template <class Element> void DList<Element>::
		addBefore(Element *next_el, Element *new_el)
{
	/* Set the next pointer of the new element to next_el. We do
	 * this regardless of the state of the list. */
	new_el->BASE_EL(next) = next_el; 

	/* Set reverse pointers. */
	if (next_el == 0) {
		/* There is no next elememnt. We are inserting at the tail. */
		new_el->BASE_EL(prev) = tail;
		tail = new_el;
	} 
	else {
		/* There is a next element and we can access next's previous. */
		new_el->BASE_EL(prev) = next_el->BASE_EL(prev);
		next_el->BASE_EL(prev) = new_el;
	} 

	/* Set forward pointers. */
	if (new_el->BASE_EL(prev) == 0) {
		/* There is no previous element. Set the head pointer.*/
		head = new_el;
	}
	else {
		/* There is a previous element, set it's next pointer to new_el. */
		new_el->BASE_EL(prev)->BASE_EL(next) = new_el;
	}

	/* Update list length. */
	listLen++;
}

/**
 * \brief Insert an entire list immediatly after an element in this list.
 *
 * Elements are moved, not copied. Afterwards, the other list is empty. If
 * prev_el is NULL then the elements are prepended to the front of the list.
 * If prev_el is not in the list then undefined behaviour results. All
 * elements are inserted into the list at once, so this is an O(1) operation.
 */
template <class Element> void DList<Element>::
		addAfter( Element *prev_el, DList<Element> &dl )
{
	/* Do not bother if dl has no elements. */
	if ( dl.listLen == 0 )
		return;

	/* Set the previous pointer of dl.head to prev_el. We do
	 * this regardless of the state of the list. */
	dl.head->BASE_EL(prev) = prev_el; 

	/* Set forward pointers. */
	if (prev_el == 0) {
		/* There was no prev_el, we are inserting at the head. */
		dl.tail->BASE_EL(next) = head;
		head = dl.head;
	} 
	else {
		/* There was a prev_el, we can access previous next. */
		dl.tail->BASE_EL(next) = prev_el->BASE_EL(next);
		prev_el->BASE_EL(next) = dl.head;
	} 

	/* Set reverse pointers. */
	if (dl.tail->BASE_EL(next) == 0) {
		/* There is no next element. Set the tail pointer. */
		tail = dl.tail;
	}
	else {
		/* There is a next element. Set it's prev pointer. */
		dl.tail->BASE_EL(next)->BASE_EL(prev) = dl.tail;
	}

	/* Update the list length. */
	listLen += dl.listLen;

	/* Empty out dl. */
	dl.head = dl.tail = 0;
	dl.listLen = 0;
}

/**
 * \brief Insert an entire list immediately before an element in this list.
 *
 * Elements are moved, not copied. Afterwards, the other list is empty. If
 * next_el is NULL then the elements are appended to the end of the list. If
 * next_el is not in the list then undefined behaviour results. All elements
 * are inserted at once, so this is an O(1) operation.
 */
template <class Element> void DList<Element>::
		addBefore( Element *next_el, DList<Element> &dl )
{
	/* Do not bother if dl has no elements. */
	if ( dl.listLen == 0 )
		return;

	/* Set the next pointer of dl.tail to next_el. We do
	 * this regardless of the state of the list. */
	dl.tail->BASE_EL(next) = next_el; 

	/* Set reverse pointers. */
	if (next_el == 0) {
		/* There is no next elememnt. We are inserting at the tail. */
		dl.head->BASE_EL(prev) = tail;
		tail = dl.tail;
	} 
	else {
		/* There is a next element and we can access next's previous. */
		dl.head->BASE_EL(prev) = next_el->BASE_EL(prev);
		next_el->BASE_EL(prev) = dl.tail;
	} 

	/* Set forward pointers. */
	if (dl.head->BASE_EL(prev) == 0) {
		/* There is no previous element. Set the head pointer.*/
		head = dl.head;
	}
	else {
		/* There is a previous element, set it's next pointer to new_el. */
		dl.head->BASE_EL(prev)->BASE_EL(next) = dl.head;
	}

	/* Update list length. */
	listLen += dl.listLen;

	/* Empty out dl. */
	dl.head = dl.tail = 0;
	dl.listLen = 0;
}


/**
 * \brief Detach an element from the list.
 *
 * The element is not deleted. If the element is not in the list, then
 * undefined behaviour results.
 *
 * \returns The element detached.
 */
template <class Element> Element *DList<Element>::
		detach(Element *el)
{
	/* Set forward pointers to skip over el. */
	if (el->BASE_EL(prev) == 0) 
		head = el->BASE_EL(next); 
	else {
		el->BASE_EL(prev)->BASE_EL(next) =
				el->BASE_EL(next); 
	}

	/* Set reverse pointers to skip over el. */
	if (el->BASE_EL(next) == 0) 
		tail = el->BASE_EL(prev); 
	else {
		el->BASE_EL(next)->BASE_EL(prev) =
				el->BASE_EL(prev); 
	}

	/* Update List length and return element we detached. */
	listLen--;
	return el;
}

/**
 * \brief Clear the list by deleting all elements.
 *
 * Each item in the list is deleted. The list is reset to its initial state.
 */
template <class Element> void DList<Element>::empty()
{
	Element *nextToGo = 0, *cur = head;
	
	while (cur != 0)
	{
		nextToGo = cur->BASE_EL(next);
		delete cur;
		cur = nextToGo;
	}
	head = tail = 0;
	listLen = 0;
}

/**
 * \brief Clear the list by forgetting all elements.
 *
 * All elements are abandoned, not deleted. The list is reset to it's initial
 * state.
 */
template <class Element> void DList<Element>::abandon()
{
	head = tail = 0;
	listLen = 0;
}


#endif
